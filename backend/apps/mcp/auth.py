"""Authentication helpers for the standalone MCP endpoint.

The MCP process (``main:mcp_app``) is mounted outside the REST authentication
middleware, so every tool resolves its principal here. Exported MCP configs
carry a scoped token signed with the owning API key's secret; legacy callers
still pass a user JWT in the request body.
"""

from dataclasses import dataclass
from typing import Optional

import jwt
from fastapi import HTTPException, Request, status
from jwt.exceptions import InvalidTokenError
from pydantic import ValidationError
from sqlmodel import Session, select

from apps.datasource.models.datasource import CoreDatasource
from apps.system.crud.apikey_manage import get_api_key_uncached
from apps.system.crud.user import get_db_user, get_user_info_uncached
from apps.system.models.system_model import UserWsModel
from apps.system.schemas.system_schema import UserInfoDTO
from common.core import security
from common.core.config import settings
from common.core.schemas import TokenPayload

MCP_TOKEN_SCOPE = 'mcp'


@dataclass(frozen=True)
class McpScope:
    """Resources an exported MCP config is allowed to touch."""

    uid: int
    oid: int
    datasource_id: int


@dataclass(frozen=True)
class McpPrincipal:
    user: UserInfoDTO
    scope: Optional[McpScope] = None


def get_user(session: Session, token: str) -> UserInfoDTO:
    """Resolve a legacy user JWT (signed with SECRET_KEY)."""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[security.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except (InvalidTokenError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Could not validate credentials',
        )

    db_user = get_db_user(session=session, user_id=token_data.id)
    if not db_user:
        raise HTTPException(status_code=404, detail='User not found')

    session_user = UserInfoDTO.model_validate(db_user.model_dump())
    session_user.isAdmin = session_user.id == 1 and session_user.account == 'admin'
    session_user.language = 'zh-CN'
    ws_model: Optional[UserWsModel] = session.exec(
        select(UserWsModel).where(
            UserWsModel.uid == session_user.id, UserWsModel.oid == session_user.oid
        )
    ).first()
    session_user.weight = ws_model.weight if ws_model else -1
    if session_user.status != 1:
        raise HTTPException(status_code=400, detail='Inactive user')
    return session_user


def _bearer_token(request: Request) -> Optional[str]:
    header = request.headers.get('authorization') or ''
    if not header.strip():
        return None
    scheme, _, param = header.partition(' ')
    if scheme.lower() != 'bearer' or not param.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Invalid Authorization header',
        )
    return param.strip()


def _invalid_credentials() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Could not validate credentials',
    )


async def _resolve_scoped_principal(session: Session, token: str) -> McpPrincipal:
    try:
        candidate = jwt.decode(
            token,
            options={'verify_signature': False, 'verify_exp': False},
            algorithms=[security.ALGORITHM],
        )
    except InvalidTokenError:
        raise _invalid_credentials()

    if candidate.get('scope') != MCP_TOKEN_SCOPE:
        raise _invalid_credentials()

    access_key = candidate.get('access_key')
    if not access_key:
        raise _invalid_credentials()

    api_key_model = await get_api_key_uncached(session, access_key)
    if not api_key_model or not api_key_model.status:
        raise _invalid_credentials()

    try:
        payload = jwt.decode(
            token, api_key_model.secret_key, algorithms=[security.ALGORITHM]
        )
    except InvalidTokenError:
        raise _invalid_credentials()

    if payload.get('scope') != MCP_TOKEN_SCOPE:
        raise _invalid_credentials()

    uid = payload.get('uid')
    oid = payload.get('oid')
    datasource_id = payload.get('datasource_id')
    if (
        not isinstance(uid, int)
        or not isinstance(oid, int)
        or not isinstance(datasource_id, int)
        or uid != api_key_model.uid
    ):
        raise _invalid_credentials()

    session_user = await get_user_info_uncached(session=session, user_id=uid)
    if not session_user or session_user.status != 1:
        raise _invalid_credentials()

    # The scoped workspace must still be one the user belongs to. Administrators
    # can switch to any workspace, matching ``user_ws_options``.
    is_admin = session_user.id == 1 and session_user.account == 'admin'
    if not is_admin:
        ws_model: Optional[UserWsModel] = session.exec(
            select(UserWsModel).where(
                UserWsModel.uid == uid, UserWsModel.oid == oid
            )
        ).first()
        if not ws_model:
            raise _invalid_credentials()
        session_user.weight = ws_model.weight
    session_user.oid = oid

    datasource = session.get(CoreDatasource, datasource_id)
    if not datasource or int(datasource.oid) != oid:
        raise _invalid_credentials()

    return McpPrincipal(
        user=session_user,
        scope=McpScope(uid=uid, oid=oid, datasource_id=datasource_id),
    )


async def resolve_mcp_principal(
    session: Session, request: Request, token: Optional[str] = None
) -> McpPrincipal:
    """Resolve the caller from the scoped Authorization header or legacy token.

    The Authorization header always wins; when present it must be a valid
    scoped token. A bad header never falls back to the body token.
    """
    bearer = _bearer_token(request)
    if bearer is not None:
        return await _resolve_scoped_principal(session, bearer)
    if token:
        return McpPrincipal(user=get_user(session, token), scope=None)
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Missing MCP credentials',
    )
