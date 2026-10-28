"""LangBot application-center single sign-on.

LangBot authenticates the user and calls the ticket endpoint server-to-server
with an HMAC-SHA256 signature. SqlBot answers with a one-time ticket; the
browser redeems it together with an HttpOnly binding cookie that LangBot set
scoped to the SqlBot mount point. A leaked redirect URL alone cannot be used
from another browser.

Invariants (do not relax):

* the signature covers version, timestamp, nonce, method, raw path and the
  SHA-256 of the raw body;
* nonces and tickets are consumed atomically and expire quickly;
* both endpoints return explicit ``JSONResponse`` objects so the global
  response wrapper does not double-wrap them;
* tickets, cookies, signatures and the shared secret are never logged.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import secrets
import time
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

from apps.system.crud.user import clean_user_cache
from apps.system.models.system_model import UserWsModel
from apps.system.models.user import UserModel
from common.core.config import settings
from common.core.deps import SessionDep
from common.core.security import create_access_token, md5pwd

router = APIRouter(tags=["langbot_sso"], prefix="/system/langbot/sso")

_SSO_VERSION = "v1"
_MAX_BODY_BYTES = 8 * 1024
_MAX_ACCOUNT_LENGTH = 100
_NONCE_RE = re.compile(r"^[0-9a-fA-F]{16,64}$")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Process-local one-time state. SqlBot must keep a single worker; restarting it
# merely invalidates unredeemed tickets, and the user re-enters from LangBot.
_ticket_store: dict[str, dict] = {}
_nonce_store: dict[str, float] = {}
_store_lock = asyncio.Lock()

_ERROR_INVALID_SIGNATURE = "invalid_signature"
_ERROR_TICKET_INVALID = "sso_ticket_invalid"
_ERROR_ACCOUNT_REJECTED = "account_rejected"
_ERROR_ACCOUNT_CONFLICT = "account_conflict"


def _sso_available() -> bool:
    return bool(settings.LANGBOT_SSO_ENABLED and len(settings.LANGBOT_SSO_SHARED_SECRET) >= 16)


def _error(status_code: int, code: str) -> JSONResponse:
    return JSONResponse({"code": code, "data": None, "msg": code}, status_code=status_code)


def _binding_cookie_path() -> str:
    context_path = (settings.CONTEXT_PATH or "").rstrip("/")
    return f"{context_path}/" if context_path else "/"


def _prune_expired(now: float) -> None:
    for key in [key for key, expires_at in _nonce_store.items() if expires_at <= now]:
        _nonce_store.pop(key, None)
    for key in [key for key, record in _ticket_store.items() if record["exp"] <= now]:
        _ticket_store.pop(key, None)


def _signing_string(*, timestamp: str, nonce: str, method: str, path: str, body_hash: str) -> str:
    return "\n".join([_SSO_VERSION, timestamp, nonce, method.upper(), path, body_hash])


async def _verify_signed_request(request: Request) -> tuple[bool, bytes]:
    """Validate the S2S signature and record the nonce.

    Returns ``(True, raw_body)`` on success and ``(False, b"")`` otherwise.
    """
    if request.headers.get("X-LangBot-SSO-Version") != _SSO_VERSION:
        return False, b""

    body = await request.body()
    if len(body) > _MAX_BODY_BYTES:
        return False, b""

    timestamp_raw = request.headers.get("X-LangBot-SSO-Timestamp", "")
    nonce = request.headers.get("X-LangBot-SSO-Nonce", "")
    signature = request.headers.get("X-LangBot-SSO-Signature", "")
    if not _NONCE_RE.fullmatch(nonce) or not _HEX64_RE.fullmatch(signature):
        return False, b""
    try:
        timestamp = int(timestamp_raw)
    except (TypeError, ValueError):
        return False, b""

    now = time.time()
    if abs(now - timestamp) > settings.LANGBOT_SSO_CLOCK_SKEW_SECONDS:
        return False, b""

    expected = hmac.new(
        settings.LANGBOT_SSO_SHARED_SECRET.encode(),
        _signing_string(
            timestamp=timestamp_raw,
            nonce=nonce,
            method=request.method,
            path=request.scope.get("path") or request.url.path,
            body_hash=hashlib.sha256(body).hexdigest(),
        ).encode(),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature.lower(), expected):
        return False, b""

    async with _store_lock:
        _prune_expired(now)
        if _nonce_store.get(nonce, 0.0) > now:
            return False, b""
        _nonce_store[nonce] = now + settings.LANGBOT_SSO_NONCE_TTL_SECONDS

    return True, body


def _normalize_account(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    account = value.strip()
    if not account or len(account) > _MAX_ACCOUNT_LENGTH:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in account):
        return None
    return account


def _find_user(session: Session, account: str) -> Optional[UserModel]:
    user = session.exec(select(UserModel).where(UserModel.account == account)).first()
    if user is not None:
        return user
    # Case-insensitive fallback keeps identities stable when an upstream
    # directory changes the capitalization of a username.
    return session.exec(select(UserModel).where(func.lower(UserModel.account) == account.lower())).first()


def _ensure_membership(session: Session, uid: int, oid: int) -> None:
    membership = session.exec(
        select(UserWsModel).where(UserWsModel.uid == uid, UserWsModel.oid == oid)
    ).first()
    if membership is None:
        session.add(UserWsModel(uid=uid, oid=oid, weight=0))
        session.flush()


def _check_existing_user(user: UserModel) -> Optional[str]:
    if user.id == 1 or (user.account or "").strip().lower() == "admin":
        return _ERROR_ACCOUNT_REJECTED
    if user.status != 1:
        return _ERROR_ACCOUNT_REJECTED
    if user.origin is not None and user.origin != 0:
        return _ERROR_ACCOUNT_REJECTED
    return None


def _resolve_or_create_user(session: Session, account: str) -> tuple[Optional[UserModel], str]:
    """Return the SqlBot user behind a LangBot account, creating it on demand."""
    workspace_id = settings.LANGBOT_SSO_DEFAULT_WORKSPACE_ID

    user = _find_user(session, account)
    if user is not None:
        rejection = _check_existing_user(user)
        if rejection is not None:
            return None, rejection
        if user.oid in (None, 0):
            user.oid = workspace_id
            session.add(user)
        _ensure_membership(session, user.id, user.oid)
        session.flush()
        return user, ""

    user = UserModel(
        account=account,
        name=account,
        oid=workspace_id,
        password=md5pwd(secrets.token_urlsafe(32)),
        email="",
        status=1,
        origin=0,
        language="zh-CN",
    )
    session.add(user)
    try:
        session.flush()
    except IntegrityError:
        # A concurrent request may have created the same account (or the name
        # collides with a different account). Re-read once, then fail closed.
        session.rollback()
        user = _find_user(session, account)
        if user is None:
            return None, _ERROR_ACCOUNT_CONFLICT
        rejection = _check_existing_user(user)
        if rejection is not None:
            return None, rejection
        if user.oid in (None, 0):
            user.oid = workspace_id
            session.add(user)
        _ensure_membership(session, user.id, user.oid)
        session.flush()
        return user, ""

    _ensure_membership(session, user.id, workspace_id)
    session.flush()
    return user, ""


@router.post("/ticket")
async def issue_ticket(request: Request, session: SessionDep) -> JSONResponse:
    """Mint a one-time ticket for a LangBot account (server-to-server only)."""
    if not _sso_available():
        return _error(503, "langbot_sso_disabled")

    verified, raw_body = await _verify_signed_request(request)
    if not verified:
        return _error(401, _ERROR_INVALID_SIGNATURE)

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return _error(400, "invalid_request")
    if not isinstance(payload, dict):
        return _error(400, "invalid_request")

    account = _normalize_account(payload.get("account"))
    binding_hash = payload.get("binding_hash")
    if account is None or not isinstance(binding_hash, str) or not _HEX64_RE.fullmatch(binding_hash):
        return _error(400, "invalid_request")

    user, rejection = _resolve_or_create_user(session, account)
    if user is None:
        status_code = 409 if rejection == _ERROR_ACCOUNT_CONFLICT else 403
        return _error(status_code, rejection)

    await clean_user_cache(user.id)

    ticket = secrets.token_urlsafe(32)
    ticket_hash = hashlib.sha256(ticket.encode()).hexdigest()
    now = time.time()
    ttl = settings.LANGBOT_SSO_TICKET_TTL_SECONDS
    async with _store_lock:
        _prune_expired(now)
        _ticket_store[ticket_hash] = {
            "uid": user.id,
            "binding_hash": binding_hash.lower(),
            "exp": now + ttl,
        }

    return JSONResponse({"ticket": ticket, "expires_in": ttl})


@router.post("/exchange")
async def exchange_ticket(request: Request, session: SessionDep) -> JSONResponse:
    """Redeem a ticket from the browser and issue a normal SqlBot token."""
    if not _sso_available():
        return _error(503, "langbot_sso_disabled")

    try:
        payload = await request.json()
    except (ValueError, UnicodeDecodeError):
        return _error(400, "invalid_request")
    if not isinstance(payload, dict):
        return _error(400, "invalid_request")

    ticket = payload.get("ticket")
    binding = request.cookies.get(settings.LANGBOT_SSO_BINDING_COOKIE_NAME)
    if not isinstance(ticket, str) or not ticket or not binding:
        return _error(401, _ERROR_TICKET_INVALID)

    ticket_hash = hashlib.sha256(ticket.encode()).hexdigest()
    binding_hash = hashlib.sha256(binding.encode()).hexdigest()
    now = time.time()
    async with _store_lock:
        _prune_expired(now)
        record = _ticket_store.get(ticket_hash)
        if record is None or record["exp"] <= now:
            return _error(401, _ERROR_TICKET_INVALID)
        if not hmac.compare_digest(record["binding_hash"], binding_hash):
            # Do not consume a valid ticket when the browser lacks the binding
            # cookie; the legitimate holder can still redeem it in time.
            return _error(401, _ERROR_TICKET_INVALID)
        _ticket_store.pop(ticket_hash, None)

    user = session.get(UserModel, record["uid"])
    if user is None or _check_existing_user(user) is not None or not user.oid:
        return _error(401, _ERROR_TICKET_INVALID)

    token = create_access_token(
        {"id": user.id, "account": user.account, "oid": user.oid},
        timedelta(minutes=settings.LANGBOT_SSO_TOKEN_TTL_MINUTES),
    )
    response = JSONResponse(
        {
            "code": 0,
            "data": {
                "access_token": token,
                "token_type": "bearer",
                "platform_info": None,
                "need_change_pwd": False,
            },
            "msg": None,
        }
    )
    response.delete_cookie(settings.LANGBOT_SSO_BINDING_COOKIE_NAME, path=_binding_cookie_path())
    return response
