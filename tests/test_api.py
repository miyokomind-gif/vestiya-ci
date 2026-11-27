import os, json, uuid, pytest, psycopg, hmac, hashlib, time
from fastapi.testclient import TestClient

os.environ.setdefault("VESTIYA_DB_DSN", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("VESTIYA_SESSION_SECRET_HEX", "a" * 64)

from app.main import app, SECRET_BYTES

ADMIN = os.environ.get("VESTIYA_ADMIN_DSN", "")
APP_DSN = os.environ.get("VESTIYA_DB_DSN", "")
SECRET_HEX = os.environ.get("VESTIYA_SESSION_SECRET_HEX", "a" * 64)
client = TestClient(app)

@pytest.fixture
def seed():
    if not ADMIN:
        pytest.skip("VESTIYA_ADMIN_DSN not set")
    ws_a, ws_b = str(uuid.uuid4()), str(uuid.uuid4())
    u_own, u_mem, u_view, u_out = (str(uuid.uuid4()) for _ in range(4))
    with psycopg.connect(ADMIN, autocommit=True) as c, c.cursor() as cur:
        cur.execute(
            "INSERT INTO public.workspace(workspace_id,kind,display_name) VALUES "
            "(%s,'personal','A'),(%s,'personal','B')", (ws_a, ws_b))
        cur.execute(
            "INSERT INTO public.app_user(user_id,display_name) VALUES "
            "(%s,'o'),(%s,'m'),(%s,'v'),(%s,'x')", (u_own, u_mem, u_view, u_out))
        cur.execute(
            "INSERT INTO auth.workspace_membership(workspace_id,user_id,role) VALUES "
            "(%s,%s,'owner'),(%s,%s,'member'),(%s,%s,'viewer'),(%s,%s,'owner')",
            (ws_a, u_own, ws_a, u_mem, ws_a, u_view, ws_b, u_out))
    return dict(ws_a=ws_a, ws_b=ws_b, own=u_own, mem=u_mem, view=u_view, out=u_out)

def mint_token(user_id: str, workspace_id: str, ttl: int = 300) -> str:
    exp = int(time.time()) + ttl
    nonce = uuid.uuid4().hex
    msg = f"{user_id}.{workspace_id}.{exp}.{nonce}"
    sig = hmac.new(SECRET_BYTES, msg.encode(), hashlib.sha256).hexdigest()
    return f"{msg}.{sig}"

def H(t=None, k=None):
    h = {}
    if t is not None: h["X-Vestiya-Token"] = t
    if k is not None: h["Idempotency-Key"] = k
    return h

def test_secret_matches_database():
    if not ADMIN: pytest.skip("VESTIYA_ADMIN_DSN not set")
    with psycopg.connect(ADMIN, autocommit=True) as c, c.cursor() as cur:
        cur.execute("SELECT encode(secret,'hex') FROM public.vestiya_session_secret WHERE id=1")
        row = cur.fetchone()
        assert row is not None, "session secret row missing"
        assert row[0] == SECRET_HEX, "DB secret != app secret"

def test_app_role_and_item_rls_enforced(seed):
    with psycopg.connect(APP_DSN, autocommit=True) as c, c.cursor() as cur:
        cur.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user")
        assert cur.fetchone() == (False, False)
        cur.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relname = 'item'")
        assert cur.fetchone() == (True, True)

    tok_a = mint_token(seed["own"], seed["ws_a"])
    tok_b = mint_token(seed["out"], seed["ws_b"])
    item_id = client.post("/items", json={"asset_type": "garment", "title": "RLS-Item"}, headers=H(tok_a, "rls-create-1")).json()["item_id"]

    with psycopg.connect(APP_DSN, autocommit=False) as c, c.cursor() as cur:
        cur.execute("SELECT set_config('app.session_token', %s, true)", (tok_b,))
        cur.execute("SELECT count(*) FROM public.item WHERE item_id = %s", (item_id,))
        assert cur.fetchone()[0] == 0
        c.rollback()

def test_apikey_bound_to_all_protected_routes():
    s = app.openapi()
    assert "ApiKeyAuth" in s["components"]["securitySchemes"]
    protected_ops = [
        ("/items", "post"), ("/items", "get"), ("/items/{item_id}", "get"),
        ("/items/{item_id}/move", "post"), ("/items/{item_id}/condition", "post"),
        ("/items/{item_id}/ownership", "post"), ("/items/{item_id}/usage", "post"),
    ]
    for path, method in protected_ops:
        op_security = s["paths"][path][method].get("security", [])
        assert {"ApiKeyAuth": []} in op_security, f"ApiKeyAuth missing on {method.upper()} {path}"

def test_openapi_error_documentation():
    s = app.openapi()
    
    def assert_error_schema(response):
        assert "content" in response
        content = response["content"]
        assert "application/json" in content
        schema = content["application/json"]["schema"]
        assert schema.get("$ref", "").endswith("/ErrorResponse")

    for path in ["/items", "/items/{item_id}/move", "/items/{item_id}/condition", "/items/{item_id}/ownership", "/items/{item_id}/usage"]:
        responses = s["paths"][path]["post"]["responses"]
        for code in ["401", "403", "409", "500"]:
            assert code in responses, f"Missing {code} on POST {path}"
            assert_error_schema(responses[code])
    
    # GET /items/{item_id} must have 401, 404, 500
    responses = s["paths"]["/items/{item_id}"]["get"]["responses"]
    for code in ["401", "404", "500"]:
        assert code in responses, f"Missing {code} on GET /items/{{item_id}}"
        assert_error_schema(responses[code])

    # GET /items must have 401, 500
    responses = s["paths"]["/items"]["get"]["responses"]
    for code in ["401", "500"]:
        assert code in responses, f"Missing {code} on GET /items"
        assert_error_schema(responses[code])

    # /auth/session must have 403
    responses = s["paths"]["/auth/session"]["post"]["responses"]
    assert "403" in responses, "Missing 403 on POST /auth/session"
    assert_error_schema(responses["403"])

def test_openapi_artifact():
    with open("openapi.json", "w", encoding="utf-8") as f:
        json.dump(app.openapi(), f, ensure_ascii=False, indent=2)

def test_missing_token_401():
    assert client.post("/items", json={"asset_type": "g", "title": "T"}, headers=H(k="z")).status_code == 401

def test_mock_session_disabled_403():
    r = client.post("/auth/session", json={"user_id": str(uuid.uuid4()), "workspace_id": str(uuid.uuid4())})
    assert r.status_code == 403

def test_expired_token_401(seed):
    t = mint_token(seed["own"], seed["ws_a"], ttl=-10)
    assert client.post("/items", json={"asset_type": "g", "title": "T"}, headers=H(t, "e1")).status_code == 401

def test_missing_idem_422(seed):
    t = mint_token(seed["own"], seed["ws_a"])
    assert client.post("/items", json={"asset_type": "g", "title": "T"}, headers=H(t)).status_code == 422

def test_invalid_condition_422(seed):
    t = mint_token(seed["own"], seed["ws_a"])
    i = client.post("/items", json={"asset_type": "g", "title": "T"}, headers=H(t, "c0")).json()["item_id"]
    assert client.post(f"/items/{i}/condition", json={"p_condition": "shiny"}, headers=H(t, "c1")).status_code == 422

def test_full_lifecycle(seed):
    t = mint_token(seed["own"], seed["ws_a"])
    r = client.post("/items", json={"asset_type": "garment", "title": "Coat"}, headers=H(t, "l1"))
    assert r.status_code == 201, r.text
    i = r.json()["item_id"]
    assert client.get(f"/items/{i}", headers=H(t)).status_code == 200
    assert client.post(f"/items/{i}/move", json={"p_to_location": None}, headers=H(t, "l2")).status_code == 200
    assert client.post(f"/items/{i}/condition", json={"p_condition": "good"}, headers=H(t, "l3")).status_code == 200
    assert client.post(f"/items/{i}/usage", json={"p_payload": {"h": 2}}, headers=H(t, "l4")).status_code == 200
    assert any(x["item_id"] == i for x in client.get("/items", headers=H(t)).json())

def test_ownership_actually_changes(seed):
    t = mint_token(seed["own"], seed["ws_a"])
    i = client.post("/items", json={"asset_type": "g", "title": "W"}, headers=H(t, "o1")).json()["item_id"]
    assert client.get(f"/items/{i}", headers=H(t)).json()["owner_user_id"] == seed["own"]
    assert client.post(f"/items/{i}/ownership", json={"p_to_user": seed["mem"]}, headers=H(t, "o2")).status_code == 200
    assert client.get(f"/items/{i}", headers=H(t)).json()["owner_user_id"] == seed["mem"]

def test_ownership_requires_owner(seed):
    t_o = mint_token(seed["own"], seed["ws_a"])
    t_m = mint_token(seed["mem"], seed["ws_a"])
    i = client.post("/items", json={"asset_type": "g", "title": "X"}, headers=H(t_o, "p1")).json()["item_id"]
    assert client.post(f"/items/{i}/ownership", json={"p_to_user": seed["mem"]}, headers=H(t_m, "p2")).status_code == 403

def test_idempotency_replay_and_conflict(seed):
    t = mint_token(seed["own"], seed["ws_a"])
    body = {"asset_type": "g", "title": "Same"}
    i1 = client.post("/items", json=body, headers=H(t, "r1")).json()["item_id"]
    i2 = client.post("/items", json=body, headers=H(t, "r1")).json()["item_id"]
    assert i1 == i2
    assert client.post("/items", json={"asset_type": "g", "title": "Other"}, headers=H(t, "r1")).status_code == 409

def test_workspace_isolation(seed):
    t_a = mint_token(seed["own"], seed["ws_a"])
    i = client.post("/items", json={"asset_type": "g", "title": "S"}, headers=H(t_a, "s1")).json()["item_id"]
    t_b = mint_token(seed["out"], seed["ws_b"])
    assert client.get("/items", headers=H(t_b)).json() == []
    assert client.get(f"/items/{i}", headers=H(t_b)).status_code == 404

def test_viewer_cannot_write(seed):
    t = mint_token(seed["view"], seed["ws_a"])
    assert client.post("/items", json={"asset_type": "g", "title": "V"}, headers=H(t, "v1")).status_code == 403
