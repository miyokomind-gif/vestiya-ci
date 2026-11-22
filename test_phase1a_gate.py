import os, hmac, hashlib, time, uuid, concurrent.futures
import psycopg, pytest

ADMIN_DSN = os.environ["VESTIYA_ADMIN_DSN"]
APP_DSN   = os.environ["VESTIYA_APP_DSN"]
SECRET    = bytes.fromhex(os.environ["VESTIYA_SESSION_SECRET_HEX"])


def _token(uid, wid, ttl=300, tamper=False):
    exp = int(time.time()) + ttl
    msg = f"{uid}.{wid}.{exp}.{uuid.uuid4().hex}"
    sig = hmac.new(SECRET, msg.encode(), hashlib.sha256).hexdigest()
    if tamper:
        sig = ("0" if sig[0] != "0" else "1") + sig[1:]
    return f"{msg}.{sig}"


def _bind(conn, token):
    with conn.cursor() as cur:
        cur.execute("SELECT set_config('app.session_token', %s, true)", (token or "",))


@pytest.fixture
def seed():
    ws_a, ws_b = str(uuid.uuid4()), str(uuid.uuid4())
    u_own, u_mem, u_view, u_out = (str(uuid.uuid4()) for _ in range(4))
    with psycopg.connect(ADMIN_DSN, autocommit=False) as c:
        with c.cursor() as cur:
            cur.execute("INSERT INTO public.workspace (workspace_id, kind, display_name) VALUES "
                        "(%s, 'personal', 'WS-A'), (%s, 'personal', 'WS-B')", (ws_a, ws_b))
            cur.execute("INSERT INTO public.app_user (user_id, display_name) VALUES "
                        "(%s, 'owner'), (%s, 'member'), (%s, 'viewer'), (%s, 'outsider')",
                        (u_own, u_mem, u_view, u_out))
            cur.execute("INSERT INTO auth.workspace_membership (workspace_id, user_id, role) VALUES "
                        "(%s, %s, 'owner'), (%s, %s, 'member'), (%s, %s, 'viewer'), (%s, %s, 'owner')",
                        (ws_a, u_own, ws_a, u_mem, ws_a, u_view, ws_b, u_out))
        c.commit()
    return dict(ws_a=ws_a, ws_b=ws_b, u_own=u_own, u_mem=u_mem, u_view=u_view, u_out=u_out)


def test_full_lifecycle(seed):
    tok = _token(seed["u_own"], seed["ws_a"])
    with psycopg.connect(APP_DSN, autocommit=False) as c:
        _bind(c, tok)
        with c.cursor() as cur:
            cur.execute("SELECT public.create_item(%s, 'garment', 'Coat', p_qr_value=>'QR-COAT')", (tok,))
            item = cur.fetchone()[0]
            cur.execute("SELECT public.move_item(%s, %s, NULL::uuid, 'tidy')", (tok, item))
            cur.execute("SELECT public.set_item_condition(%s, %s, 'good', 'inspected')", (tok, item))
            cur.execute("SELECT event_type, item_seq FROM public.domain_event "
                        "WHERE subject_item_id = %s ORDER BY item_seq", (item,))
            assert [(r[0], r[1]) for r in cur.fetchall()] == [
                ("ITEM_CREATED", 1), ("ITEM_MOVED", 2), ("ITEM_CONDITION_CHANGED", 3)]
            cur.execute("SELECT item_id FROM public.item_identifier WHERE value='QR-COAT'")
            assert cur.fetchone()[0] == item
        c.commit()


def test_workspace_member_view_accessible(seed):
    tok = _token(seed["u_own"], seed["ws_a"])
    with psycopg.connect(APP_DSN, autocommit=False) as c:
        _bind(c, tok)
        with c.cursor() as cur:
            cur.execute("SELECT count(*) FROM public.workspace_member WHERE workspace_id = %s",
                        (seed["ws_a"],))
            assert cur.fetchone()[0] == 3
        c.rollback()


def test_rls_isolation_and_private_membership(seed):
    tok_own = _token(seed["u_own"], seed["ws_a"])
    tok_out = _token(seed["u_out"], seed["ws_b"])
    with psycopg.connect(APP_DSN, autocommit=False) as c:
        _bind(c, tok_own)
        with c.cursor() as cur:
            cur.execute("SELECT public.create_item(%s, 'garment', 'Scoped')", (tok_own,))
            item_a = cur.fetchone()[0]
        c.commit()
    with psycopg.connect(APP_DSN, autocommit=False) as c:
        _bind(c, tok_out)
        with c.cursor() as cur:
            cur.execute("SELECT count(*) FROM public.item WHERE item_id = %s", (item_a,))
            assert cur.fetchone()[0] == 0
            cur.execute("SAVEPOINT sp")
            with pytest.raises(psycopg.Error) as e:
                cur.execute("SELECT * FROM auth.workspace_membership")
            assert e.value.sqlstate == "42501"
            cur.execute("ROLLBACK TO SAVEPOINT sp")
        c.rollback()


def test_token_validation_and_roles(seed):
    tok_view = _token(seed["u_view"], seed["ws_a"])
    for bad in (_token(seed["u_own"], seed["ws_a"], ttl=-10),
                _token(seed["u_own"], seed["ws_a"], tamper=True),
                "invalid.token.structure"):
        with psycopg.connect(APP_DSN, autocommit=False) as c:
            with c.cursor() as cur:
                cur.execute("SAVEPOINT sp")
                with pytest.raises(psycopg.Error) as e:
                    cur.execute("SELECT public.create_item(%s, 'garment', 'X')", (bad,))
                assert e.value.sqlstate == "42501"
                cur.execute("ROLLBACK TO SAVEPOINT sp")
            c.rollback()
    with psycopg.connect(APP_DSN, autocommit=False) as c:
        _bind(c, tok_view)
        with c.cursor() as cur:
            cur.execute("SAVEPOINT spv")
            with pytest.raises(psycopg.Error) as e:
                cur.execute("SELECT public.create_item(%s, 'garment', 'VWrite')", (tok_view,))
            assert e.value.sqlstate == "42501"
            cur.execute("ROLLBACK TO SAVEPOINT spv")
        c.rollback()


def test_append_only_blocks_privileged_mutation(seed):
    tok = _token(seed["u_own"], seed["ws_a"])
    with psycopg.connect(APP_DSN, autocommit=False) as c:
        _bind(c, tok)
        with c.cursor() as cur:
            cur.execute("SELECT public.create_item(%s, 'garment', 'Immutable')", (tok,))
            item = cur.fetchone()[0]
            cur.execute("SELECT event_id FROM public.domain_event WHERE subject_item_id = %s", (item,))
            ev = cur.fetchone()[0]
        c.commit()
    with psycopg.connect(ADMIN_DSN, autocommit=False) as c:
        with c.cursor() as cur:
            cur.execute("SELECT has_table_privilege(current_user, 'public.domain_event', 'UPDATE'), "
                        "       has_table_privilege(current_user, 'public.domain_event', 'DELETE')")
            assert cur.fetchone() == (True, True)
            cur.execute("SAVEPOINT sp")
            with pytest.raises(psycopg.Error) as e:
                cur.execute("UPDATE public.domain_event SET reason_ref='x' WHERE event_id=%s", (ev,))
            assert e.value.sqlstate == "42501"
            cur.execute("ROLLBACK TO SAVEPOINT sp")
            cur.execute("SAVEPOINT spd")
            with pytest.raises(psycopg.Error) as e:
                cur.execute("DELETE FROM public.domain_event WHERE event_id=%s", (ev,))
            assert e.value.sqlstate == "42501"
            cur.execute("ROLLBACK TO SAVEPOINT spd")
        c.rollback()


def test_idempotency_and_concurrency(seed):
    tok = _token(seed["u_own"], seed["ws_a"])
    with psycopg.connect(APP_DSN, autocommit=False) as c:
        _bind(c, tok)
        with c.cursor() as cur:
            cur.execute("SELECT public.create_item(%s, 'garment', 'Idem', p_idem=>'k-same')", (tok,))
            id1 = cur.fetchone()[0]
            cur.execute("SELECT public.create_item(%s, 'garment', 'Idem', p_idem=>'k-same')", (tok,))
            id2 = cur.fetchone()[0]
            assert id1 == id2
            cur.execute("SAVEPOINT spo")
            with pytest.raises(psycopg.Error) as e1:
                cur.execute("SELECT public.record_usage(%s, %s, '{\"k\":1}'::jsonb, 'ci', 'k-same')",
                            (tok, id1))
            assert e1.value.sqlstate == "42501"
            cur.execute("ROLLBACK TO SAVEPOINT spo")
            cur.execute("SAVEPOINT spp")
            with pytest.raises(psycopg.Error) as e2:
                cur.execute("SELECT public.create_item(%s, 'garment', 'Different', p_idem=>'k-same')", (tok,))
            assert e2.value.sqlstate == "42501"
            cur.execute("ROLLBACK TO SAVEPOINT spp")
        c.commit()

    def worker(_):
        with psycopg.connect(APP_DSN, autocommit=False) as cc:
            _bind(cc, tok)
            with cc.cursor() as cur:
                cur.execute("SELECT public.record_usage(%s, %s, '{\"s\":1}'::jsonb, 'conc', 'k-conc')",
                            (tok, id1))
                ev = cur.fetchone()[0]
            cc.commit()
            return str(ev)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        evs = list(pool.map(worker, range(4)))
    assert len(set(evs)) == 1


def test_location_cycle(seed):
    ws = seed["ws_a"]
    l1, l2, l3 = (str(uuid.uuid4()) for _ in range(3))
    with psycopg.connect(ADMIN_DSN, autocommit=False) as c:
        with c.cursor() as cur:
            cur.execute("INSERT INTO public.location (location_id, workspace_id, kind, name) "
                        "VALUES (%s, %s, 'building', 'L1')", (l1, ws))
            cur.execute("INSERT INTO public.location (location_id, workspace_id, kind, name, parent_id) "
                        "VALUES (%s, %s, 'room', 'L2', %s)", (l2, ws, l1))
            cur.execute("INSERT INTO public.location (location_id, workspace_id, kind, name, parent_id) "
                        "VALUES (%s, %s, 'shelf', 'L3', %s)", (l3, ws, l2))
            for target in (l2, l3):
                cur.execute("SAVEPOINT sp")
                with pytest.raises(psycopg.Error) as e:
                    cur.execute("UPDATE public.location SET parent_id = %s WHERE location_id = %s",
                                (target, l1))
                assert e.value.sqlstate == "23P01"
                cur.execute("ROLLBACK TO SAVEPOINT sp")
        c.rollback()
