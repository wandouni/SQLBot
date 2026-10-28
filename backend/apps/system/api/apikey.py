
import re
import secrets
import time
from urllib.parse import urlsplit

import jwt
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlmodel import func, select
from apps.datasource.models.datasource import CoreDatasource
from apps.system.crud.apikey_manage import clear_api_key_cache
from apps.system.models.system_model import ApiKeyModel
from apps.system.schemas.system_schema import ApikeyGridItem, ApikeyStatus
from common.core import security
from common.core.config import settings
from common.core.deps import CurrentUser, SessionDep
from common.utils.time import get_timestamp

router = APIRouter(tags=["system_apikey"], prefix="/system/apikey", include_in_schema=False)
from common.audit.models.log_model import OperationType, OperationModules
from common.audit.schemas.logger_decorator import LogConfig, system_log

@router.get("")
async def grid(session: SessionDep, current_user: CurrentUser) -> list[ApikeyGridItem]:
    query = select(ApiKeyModel).where(ApiKeyModel.uid == current_user.id).order_by(ApiKeyModel.create_time.desc())
    return session.exec(query).all()

@router.post("")
@system_log(LogConfig(operation_type=OperationType.CREATE, module=OperationModules.API_KEY,result_id_expr='result.self'))
async def create(session: SessionDep, current_user: CurrentUser):
    count = session.exec(select(func.count()).select_from(ApiKeyModel).where(ApiKeyModel.uid == current_user.id)).one()
    if count >= 5:
        raise ValueError("Maximum of 5 API keys allowed")
    access_key = secrets.token_urlsafe(16)
    secret_key = secrets.token_urlsafe(32)
    api_key = ApiKeyModel(
        access_key=access_key,
        secret_key=secret_key,
        create_time=get_timestamp(),
        uid=current_user.id,
        status=True
    )
    session.add(api_key)
    session.commit()
    return api_key.id

@router.put("/status")
@system_log(LogConfig(operation_type=OperationType.UPDATE, module=OperationModules.API_KEY,resource_id_expr='id'))
async def status(session: SessionDep, current_user: CurrentUser, dto: ApikeyStatus):
    api_key = session.get(ApiKeyModel, dto.id)
    if not api_key:
        raise ValueError("API Key not found")
    if api_key.uid != current_user.id:
        raise PermissionError("No permission to modify this API Key")
    if dto.status == api_key.status:
        return
    api_key.status = dto.status
    await clear_api_key_cache(api_key.access_key)
    session.add(api_key)
    session.commit()

@router.delete("/{id}")
@system_log(LogConfig(operation_type=OperationType.DELETE, module=OperationModules.API_KEY,resource_id_expr='id'))
async def delete(session: SessionDep, current_user: CurrentUser, id: int):
    api_key = session.get(ApiKeyModel, id)
    if not api_key:
        raise ValueError("API Key not found")
    if api_key.uid != current_user.id:
        raise PermissionError("No permission to delete this API Key")
    await clear_api_key_cache(api_key.access_key)
    session.delete(api_key)
    session.commit()


def _mcp_public_url(request: Request) -> str:
    configured = settings.MCP_PUBLIC_URL.strip().rstrip("/")
    if configured:
        parsed = urlsplit(configured)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("MCP_PUBLIC_URL must be an absolute http(s) URL")
        if not parsed.path:
            configured = f"{configured}/mcp"
        return configured
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.url.hostname or "localhost"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{scheme}://{host}:{settings.MCP_PORT}/mcp"


def _mcp_server_name(name: str, datasource_id: int) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", (name or "").strip()).strip("-._")
    return f"sqlbot-{(slug or 'datasource')[:40]}-{datasource_id}"


@router.get("/{id}/mcp-config")
async def mcp_config(session: SessionDep, current_user: CurrentUser, request: Request,
                     id: int, datasource_id: int):
    """Export a scoped MCP config bound to one datasource.

    The token is signed with this API key's secret and only works on the MCP
    endpoint; disabling or deleting the key revokes it.
    """
    api_key = session.get(ApiKeyModel, id)
    if not api_key:
        raise ValueError("API Key not found")
    if api_key.uid != current_user.id:
        raise PermissionError("No permission to access this API Key")
    if not api_key.status:
        raise ValueError("API Key is disabled")

    datasource = session.get(CoreDatasource, datasource_id)
    if not datasource or int(datasource.oid) != int(current_user.oid):
        raise PermissionError("Datasource does not belong to current workspace")

    token = jwt.encode(
        {
            "access_key": api_key.access_key,
            "scope": "mcp",
            "uid": int(api_key.uid),
            "oid": int(datasource.oid),
            "datasource_id": int(datasource.id),
            "iat": int(time.time()),
        },
        api_key.secret_key,
        algorithm=security.ALGORITHM,
    )

    url = _mcp_public_url(request)
    headers = {"Authorization": f"Bearer {token}"}
    server_name = _mcp_server_name(datasource.name, int(datasource.id))
    return JSONResponse(
        content={
            "url": url,
            "headers": headers,
            "datasource": {"id": int(datasource.id), "name": datasource.name},
            "config": {
                "mcpServers": {
                    server_name: {
                        "type": "sse",
                        "url": url,
                        "headers": headers,
                    }
                }
            },
        },
        headers={"Cache-Control": "no-store"},
    )
    