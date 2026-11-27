import os, uuid, hmac, hashlib, time, pytest, psycopg
from fastapi.testclient import TestClient
from app.main import app, db_readonly

ADMIN = os.environ["VESTIYA_ADMIN_DSN"]
APP = os.environ["VESTIYA_DB_DSN"]
SECRET = bytes.fromhex(os.environ["VESTIYA_SESSION_SECRET_HEX"])
client = TestClient(app)
NEED = "shirt_pants_formal_shoes"


def tok(uid, wid, ttl=300):
    m = f"{uid}.{wid}.{int(time.time())+ttl}.{uuid.uuid4().hex}"
    return f"{m}.{hmac.new(SECRET, m.encode(), hashlib.sha256).hexdigest()}"


@pytest.fixture
def seed():
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    o, x = str(uuid.uuid4()), str(uuid.uuid4())
    with psycopg.connect(ADMIN, autocommit=True) as c, c.cursor() as cur:
        cur.execute("INSERT INTO public.workspace(workspace_id,kind,display_name) VALUES "
                    "(%s,'personal','A'),(%s,'personal','B')", (a, b))
        cur.execute("INSERT INTO public.app_user(user_id,display_name) VALUES (%s,'o'),(%s,'x')", (o, x))
        cur.execute("INSERT INTO auth.workspace_membership(workspace_id,user_id,role) VALUES "
                    "(%s,%s,'owner'),(%s,%s,'owner')", (a, o, b, x))
    return dict(ws_a=a, ws_b=b, own=o, out=x)


def H(t, k=None):
    h = {"X-Vestiya-Token": t}
    if k:
        h["Idempotency-Key"] = k
    return h


def mk(t, at, st, cond="good"):
    r = client.post("/items", json={"asset_type": at, "title": at, "attributes": {"sub_type": st}},
                    headers=H(t, uuid.uuid4().hex))
    assert r.status_code == 201, r.text
    i = r.json()["item_id"]
    if cond != "unknown":
        assert client.post(f"/items/{i}/condition", json={"p_condition": cond},
                           headers=H(t, uuid.uuid4().hex)).status_code == 200
    return i


def ev(t, need=NEED):
    return client.post("/need/evaluate", json={"need_type": need}, headers=H(t))


def test_api_full_match(seed):
    t = tok(seed["own"], seed["ws_a"])
    mk(t, "shirt", "shirt"); mk(t, "pants", "pants"); mk(t, "formal_shoes", "formal_shoes")
    r = ev(t); assert r.status_code == 200
    d = r.json()
    assert d["status"] == "EVALUATE" and d["evaluation"]["has_sufficient_items"] is True


def test_api_fair_abstains(seed):
    t = tok(seed["own"], seed["ws_a"])
    mk(t, "shirt", "shirt", cond="fair")
    assert ev(t).json()["evaluation"]["reason_code"] == "AMBIGUOUS_DATA"


def test_api_unknown_condition_abstains(seed):
    t = tok(seed["own"], seed["ws_a"])
    mk(t, "shirt", "shirt", cond="unknown")
    assert ev(t).json()["evaluation"]["reason_code"] == "AMBIGUOUS_DATA"


def test_api_partial(seed):
    t = tok(seed["own"], seed["ws_a"])
    mk(t, "shirt", "shirt"); mk(t, "pants", "pants")
    d = ev(t).json()["evaluation"]
    assert d["has_sufficient_items"] is False and d["gaps"] == ["formal_shoes"]


def test_api_empty(seed):
    assert ev(tok(seed["own"], seed["ws_a"])).json()["evaluation"]["reason_code"] == "INSUFFICIENT_INVENTORY_DATA"


def test_api_unsupported(seed):
    assert ev(tok(seed["own"], seed["ws_a"]), "fly_to_mars").json()["evaluation"]["reason_code"] == "UNSUPPORTED_NEED_TYPE"


def test_api_empty_need_422(seed):
    t = tok(seed["own"], seed["ws_a"])
    assert client.post("/need/evaluate", json={"need_type": ""}, headers=H(t)).status_code == 422


def test_api_bad_scope_422(seed):
    t = tok(seed["own"], seed["ws_a"])
    assert client.post("/need/evaluate", json={"need_type": NEED, "scope": "x"}, headers=H(t)).status_code == 422


def test_api_extra_field_422(seed):
    t = tok(seed["own"], seed["ws_a"])
    assert client.post("/need/evaluate", json={"need_type": NEED, "purpose": "x"}, headers=H(t)).status_code == 422


def test_api_expired_401(seed):
    assert ev(tok(seed["own"], seed["ws_a"], ttl=-10)).status_code == 401


def test_api_missing_token_401():
    assert client.post("/need/evaluate", json={"need_type": NEED}).status_code == 401


def test_api_revoked_membership_403(seed):
    t = tok(seed["own"], seed["ws_a"])
    with psycopg.connect(ADMIN, autocommit=True) as c, c.cursor() as cur:
        cur.execute("DELETE FROM auth.workspace_membership WHERE workspace_id=%s AND user_id=%s",
                    (seed["ws_a"], seed["own"]))
    assert ev(t).status_code == 403


def test_api_isolation(seed):
    t_a = tok(seed["own"], seed["ws_a"])
    mk(t_a, "shirt", "shirt")
    d = ev(tok(seed["out"], seed["ws_b"])).json()
    assert d["evaluation"]["reason_code"] == "INSUFFICIENT_INVENTORY_DATA"
    assert d["evaluation"]["matched_items"] == []


def test_readonly_mode_is_on(seed):
    t = tok(seed["own"], seed["ws_a"])
    with db_readonly(t) as conn, conn.cursor() as cur:
        cur.execute("SHOW transaction_read_only")
        assert cur.fetchone()["transaction_read_only"] == "on"


def test_app_role_lacks_update_grant():
    with psycopg.connect(APP, autocommit=True) as c, c.cursor() as cur:
        cur.execute("SELECT has_table_privilege(current_user,'public.item','UPDATE')")
        assert cur.fetchone()[0] is False


def test_readonly_blocks_write_for_privileged_role():
    with psycopg.connect(ADMIN, autocommit=False) as c, c.cursor() as cur:
        cur.execute("SET TRANSACTION READ ONLY")
        cur.execute("SELECT has_table_privilege(current_user,'public.item','UPDATE')")
        assert cur.fetchone()[0] is True
        with pytest.raises(psycopg.Error) as e:
            cur.execute("UPDATE public.item SET title='x'")
        assert e.value.sqlstate == "25006"
        c.rollback()


def test_api_success_and_no_writes(seed):
    t = tok(seed["own"], seed["ws_a"])
    mk(t, "shirt", "shirt")
    q = ("SELECT (SELECT count(*) FROM public.item),(SELECT count(*) FROM public.domain_event),"
         "(SELECT count(*) FROM public.event_outbox),(SELECT count(*) FROM public.operation_idempotency),"
         "(SELECT count(*) FROM public.item_custody_history)")
    with psycopg.connect(ADMIN, autocommit=True) as c, c.cursor() as cur:
        cur.execute(q); before = cur.fetchone()
    assert ev(t).status_code == 200
    with psycopg.connect(ADMIN, autocommit=True) as c, c.cursor() as cur:
        cur.execute(q); assert cur.fetchone() == before


def test_need_route_protected():
    assert {"ApiKeyAuth": []} in app.openapi()["paths"]["/need/evaluate"]["post"]["security"]
