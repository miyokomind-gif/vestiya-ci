import os, json, hmac, hashlib, time, uuid
from contextlib import contextmanager
from datetime import date, datetime
from typing import Literal, Any
import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from app.need_engine import InventoryItem, evaluate_need

DSN = os.environ["VESTIYA_DB_DSN"]
SECRET_HEX = os.environ["VESTIYA_SESSION_SECRET_HEX"]
SECRET_BYTES = bytes.fromhex(SECRET_HEX)
MOCK_AUTH = os.environ.get("VESTIYA_ENABLE_MOCK_AUTH", "false").strip().lower() == "true"

app = FastAPI(title="VESTIYA API", version="1.5.2")
api_key_scheme = APIKeyHeader(name="X-Vestiya-Token", scheme_name="ApiKeyAuth", auto_error=False)


def require_token(token: str | None = Depends(api_key_scheme)) -> str:
    if not token or not token.strip():
        raise HTTPException(401, "Missing or empty X-Vestiya-Token")
    return token.strip()


def map_db_error(exc: psycopg.Error) -> HTTPException:
    s = exc.sqlstate
    m = (exc.diag.message_primary if exc.diag else "") or ""
    if s == "42501":
        if m == "idempotency key conflict":
            return HTTPException(409, "Idempotency key conflict")
        if m == "invalid or expired session token":
            return HTTPException(401, "Invalid or expired session token")
        if m in {"write requires member/owner role", "ownership transfer requires owner role",
                 "item not accessible", "owner must be a workspace member",
                 "target owner is not a member", "item not in workspace"}:
            return HTTPException(403, "Forbidden")
    if s == "22023" and m == "ownership unchanged":
        return HTTPException(409, "Ownership unchanged")
    return HTTPException(500, "Internal Server Error")


@contextmanager
def db(token: str):
    conn = psycopg.connect(DSN, autocommit=False, row_factory=dict_row)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.session_token', %s, true)", (token,))
        yield conn
        conn.commit()
    except psycopg.Error as e:
        conn.rollback()
        raise map_db_error(e)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def db_readonly(token: str):
    conn = psycopg.connect(DSN, autocommit=False, row_factory=dict_row)
    try:
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute("SELECT set_config('app.session_token', %s, true)", (token,))
        yield conn
        conn.commit()
    except psycopg.Error as e:
        conn.rollback()
        raise map_db_error(e)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


Cond = Literal["new", "good", "fair", "poor", "broken", "unknown"]


class SessionRequest(BaseModel):
    user_id: uuid.UUID
    workspace_id: uuid.UUID


class SessionResponse(BaseModel):
    token: str


class CreateItemRequest(BaseModel):
    asset_type: str = Field(min_length=1)
    title: str = Field(min_length=1)
    attributes: dict[str, Any] = Field(default_factory=dict)
    p_location: uuid.UUID | None = None
    p_owner: uuid.UUID | None = None
    p_qr_value: str | None = None


class MoveItemRequest(BaseModel):
    p_to_location: uuid.UUID | None
    p_reason: str | None = None


class SetConditionRequest(BaseModel):
    p_condition: Cond
    p_reason: str | None = None


class TransferOwnershipRequest(BaseModel):
    p_to_user: uuid.UUID
    p_reason: str | None = None


class RecordUsageRequest(BaseModel):
    p_payload: dict[str, Any] = Field(default_factory=dict)
    p_source: str | None = None


class CreateItemResponse(BaseModel):
    item_id: uuid.UUID


class EventResponse(BaseModel):
    event_id: uuid.UUID


class ItemRead(BaseModel):
    item_id: uuid.UUID
    workspace_id: uuid.UUID
    asset_type: str
    title: str
    attributes: dict[str, Any]
    condition_state: str
    location_id: uuid.UUID | None
    owner_user_id: uuid.UUID
    holder_user_id: uuid.UUID
    acquired_at: date | None
    warranty_until: date | None
    created_at: datetime
    updated_at: datetime
    archived_at: datetime | None


class ErrorResponse(BaseModel):
    detail: str


class NeedEvaluateRequest(BaseModel):
    model_config = {"extra": "forbid"}
    need_type: str = Field(min_length=1)
    scope: Literal["all_assets"] = "all_assets"


class NeedEvaluation(BaseModel):
    has_sufficient_items: bool | None
    matched_items: list[str]
    gaps: list[str]
    unknown_requirements: list[str]
    evidence_scope: str
    reason_code: str
    reasoning: str


class NeedEvaluateResponse(BaseModel):
    status: Literal["EVALUATE", "ABSTAIN"]
    evaluation: NeedEvaluation


ERR_READ = {
    401: {"model": ErrorResponse, "description": "Unauthorized"},
    500: {"model": ErrorResponse, "description": "Internal Server Error"},
}
ERR_WRITE = {
    401: {"model": ErrorResponse, "description": "Unauthorized"},
    403: {"model": ErrorResponse, "description": "Forbidden"},
    409: {"model": ErrorResponse, "description": "Conflict"},
    500: {"model": ErrorResponse, "description": "Internal Server Error"},
}
ERR_NEED = {
    401: {"model": ErrorResponse, "description": "Unauthorized"},
    403: {"model": ErrorResponse, "description": "Forbidden"},
    500: {"model": ErrorResponse, "description": "Internal Server Error"},
}
IDEM = Header(..., alias="Idempotency-Key", min_length=1, max_length=255)


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


@app.post("/auth/session", response_model=SessionResponse,
          responses={403: {"model": ErrorResponse, "description": "Forbidden"}})
def create_session(req: SessionRequest):
    if not MOCK_AUTH:
        raise HTTPException(403, "Mock auth is disabled")
    msg = f"{req.user_id}.{req.workspace_id}.{int(time.time()) + 300}.{uuid.uuid4().hex}"
    sig = hmac.new(SECRET_BYTES, msg.encode(), hashlib.sha256).hexdigest()
    return {"token": f"{msg}.{sig}"}


@app.post("/items", response_model=CreateItemResponse, status_code=201, responses=ERR_WRITE)
def create_item(body: CreateItemRequest, idempotency_key: str = IDEM, token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT public.create_item(%s,%s,%s,%s::jsonb,%s::uuid,%s::uuid,%s,%s)",
                    (token, body.asset_type, body.title, json.dumps(body.attributes),
                     str(body.p_location) if body.p_location else None,
                     str(body.p_owner) if body.p_owner else None,
                     body.p_qr_value, idempotency_key))
        return {"item_id": cur.fetchone()["create_item"]}


@app.get("/items", response_model=list[ItemRead], responses=ERR_READ)
def list_items(token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM public.item ORDER BY created_at")
        return cur.fetchall()


@app.get("/items/{item_id}", response_model=ItemRead,
         responses={404: {"model": ErrorResponse, "description": "Not Found"}, **ERR_READ})
def get_item(item_id: uuid.UUID, token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM public.item WHERE item_id=%s", (str(item_id),))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(404, "Item not found or not accessible")
        return row


@app.post("/items/{item_id}/move", response_model=EventResponse, responses=ERR_WRITE)
def move_item(item_id: uuid.UUID, body: MoveItemRequest, idempotency_key: str = IDEM, token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT public.move_item(%s,%s::uuid,%s::uuid,%s,%s)",
                    (token, str(item_id), str(body.p_to_location) if body.p_to_location else None,
                     body.p_reason, idempotency_key))
        return {"event_id": cur.fetchone()["move_item"]}


@app.post("/items/{item_id}/condition", response_model=EventResponse, responses=ERR_WRITE)
def set_condition(item_id: uuid.UUID, body: SetConditionRequest, idempotency_key: str = IDEM, token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT public.set_item_condition(%s,%s::uuid,%s,%s,%s)",
                    (token, str(item_id), body.p_condition, body.p_reason, idempotency_key))
        return {"event_id": cur.fetchone()["set_item_condition"]}


@app.post("/items/{item_id}/ownership", response_model=EventResponse, responses=ERR_WRITE)
def transfer_ownership(item_id: uuid.UUID, body: TransferOwnershipRequest, idempotency_key: str = IDEM, token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT public.transfer_item_ownership(%s,%s::uuid,%s::uuid,%s,%s)",
                    (token, str(item_id), str(body.p_to_user), body.p_reason, idempotency_key))
        return {"event_id": cur.fetchone()["transfer_item_ownership"]}


@app.post("/items/{item_id}/usage", response_model=EventResponse, responses=ERR_WRITE)
def record_usage(item_id: uuid.UUID, body: RecordUsageRequest, idempotency_key: str = IDEM, token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT public.record_usage(%s,%s::uuid,%s::jsonb,%s,%s)",
                    (token, str(item_id), json.dumps(body.p_payload), body.p_source, idempotency_key))
        return {"event_id": cur.fetchone()["record_usage"]}


@app.post("/need/evaluate", response_model=NeedEvaluateResponse, responses=ERR_NEED)
def need_evaluate(body: NeedEvaluateRequest, token: str = Depends(require_token)):
    with db_readonly(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT public.vestiya_active_user() AS uid, "
                    "public.vestiya_active_workspace() AS wid")
        row = cur.fetchone()
        if row is None or row["uid"] is None or row["wid"] is None:
            raise HTTPException(401, "Invalid or expired session token")
        cur.execute("SELECT public.vestiya_rls_allows_workspace(%s::uuid) AS ok",
                    (str(row["wid"]),))
        if not cur.fetchone()["ok"]:
            raise HTTPException(403, "Workspace access is not permitted for this session")
        cur.execute("SELECT item_id, asset_type, attributes, condition_state, archived_at "
                    "FROM public.item")
        rows = cur.fetchall()

    inventory = [InventoryItem(item_id=str(r["item_id"]), asset_type=r["asset_type"],
                               attributes=(r["attributes"] or {}),
                               condition_state=r["condition_state"],
                               archived_at=r["archived_at"]) for r in rows]
    res = evaluate_need(body.need_type, inventory)
    return {"status": res.status, "evaluation": {
        "has_sufficient_items": res.has_sufficient_items,
        "matched_items": res.matched_items,
        "gaps": res.gaps,
        "unknown_requirements": res.unknown_requirements,
        "evidence_scope": res.evidence_scope,
        "reason_code": res.reason_code,
        "reasoning": res.reasoning}}
