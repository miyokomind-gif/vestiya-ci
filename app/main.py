import os, json, hmac, hashlib, time, uuid
from contextlib import contextmanager
from datetime import date, datetime
from typing import Literal, Any
import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

DSN = os.environ["VESTIYA_DB_DSN"]
SECRET_BYTES = bytes.fromhex(os.environ["VESTIYA_SESSION_SECRET_HEX"])
MOCK_AUTH = os.environ.get("VESTIYA_ENABLE_MOCK_AUTH", "false").lower() == "true"

app = FastAPI(title="VESTIYA API", version="1.4.1")
api_key_scheme = APIKeyHeader(name="X-Vestiya-Token", scheme_name="ApiKeyAuth", auto_error=False)

def require_token(token: str | None = Depends(api_key_scheme)) -> str:
    if not token or not token.strip():
        raise HTTPException(401, "Missing or empty X-Vestiya-Token")
    return token.strip()

def mint_token(user_id: str, workspace_id: str, ttl: int = 300) -> str:
    msg = f"{user_id}.{workspace_id}.{int(time.time()) + ttl}.{uuid.uuid4().hex}"
    return f"{msg}.{hmac.new(SECRET_BYTES, msg.encode(), hashlib.sha256).hexdigest()}"

def map_db_error(exc: psycopg.Error) -> HTTPException:
    s = exc.sqlstate
    m = (exc.diag.message_primary if exc.diag else "") or ""
    if s == "42501":
        if m == "idempotency key conflict":
            return HTTPException(409, "Idempotency key conflict")
        if m == "invalid or expired session token":
            return HTTPException(401, "Invalid or expired session token")
        if m in {
            "write requires member/owner role",
            "ownership transfer requires owner role",
            "item not accessible",
            "owner must be a workspace member",
            "target owner is not a member",
            "item not in workspace",
        }:
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

IDEM = Header(..., alias="Idempotency-Key", min_length=1, max_length=255)

@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}

@app.post("/auth/session", response_model=SessionResponse)
def create_session(req: SessionRequest):
    if not MOCK_AUTH:
        raise HTTPException(403, "Mock session endpoint is disabled")
    return {"token": mint_token(str(req.user_id), str(req.workspace_id))}

@app.post("/items", response_model=CreateItemResponse, status_code=201)
def create_item(body: CreateItemRequest, idempotency_key: str = IDEM, token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT public.create_item(%s,%s,%s,%s::jsonb,%s::uuid,%s::uuid,%s,%s)",
                    (token, body.asset_type, body.title, json.dumps(body.attributes),
                     str(body.p_location) if body.p_location else None,
                     str(body.p_owner) if body.p_owner else None,
                     body.p_qr_value, idempotency_key))
        return {"item_id": cur.fetchone()["create_item"]}

@app.get("/items", response_model=list[ItemRead])
def list_items(token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM public.item ORDER BY created_at")
        return cur.fetchall()

@app.get("/items/{item_id}", response_model=ItemRead, responses={404: {"model": ErrorResponse}})
def get_item(item_id: uuid.UUID, token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM public.item WHERE item_id=%s", (str(item_id),))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(404, "Item not found or not accessible")
        return row

@app.post("/items/{item_id}/move", response_model=EventResponse)
def move_item(item_id: uuid.UUID, body: MoveItemRequest, idempotency_key: str = IDEM, token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT public.move_item(%s,%s::uuid,%s::uuid,%s,%s)",
                    (token, str(item_id), str(body.p_to_location) if body.p_to_location else None,
                     body.p_reason, idempotency_key))
        return {"event_id": cur.fetchone()["move_item"]}

@app.post("/items/{item_id}/condition", response_model=EventResponse)
def set_condition(item_id: uuid.UUID, body: SetConditionRequest, idempotency_key: str = IDEM, token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT public.set_item_condition(%s,%s::uuid,%s,%s,%s)",
                    (token, str(item_id), body.p_condition, body.p_reason, idempotency_key))
        return {"event_id": cur.fetchone()["set_item_condition"]}

@app.post("/items/{item_id}/ownership", response_model=EventResponse)
def transfer_ownership(item_id: uuid.UUID, body: TransferOwnershipRequest, idempotency_key: str = IDEM, token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT public.transfer_item_ownership(%s,%s::uuid,%s::uuid,%s,%s)",
                    (token, str(item_id), str(body.p_to_user), body.p_reason, idempotency_key))
        return {"event_id": cur.fetchone()["transfer_item_ownership"]}

@app.post("/items/{item_id}/usage", response_model=EventResponse)
def record_usage(item_id: uuid.UUID, body: RecordUsageRequest, idempotency_key: str = IDEM, token: str = Depends(require_token)):
    with db(token) as conn, conn.cursor() as cur:
        cur.execute("SELECT public.record_usage(%s,%s::uuid,%s::jsonb,%s,%s)",
                    (token, str(item_id), json.dumps(body.p_payload), body.p_source, idempotency_key))
        return {"event_id": cur.fetchone()["record_usage"]}
