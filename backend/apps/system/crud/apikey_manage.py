
from sqlmodel import select

from apps.system.models.system_model import ApiKeyModel
from apps.system.schemas.auth import CacheName, CacheNamespace
from common.core.deps import SessionDep
from common.core.sqlbot_cache import cache, clear_cache
from common.utils.utils import SQLBotLogUtil

async def get_api_key_uncached(session: SessionDep, access_key: str) -> ApiKeyModel | None:
    """Read an API key without the process-local auth cache.

    The MCP process is separate from the API process, so it cannot rely on the
    API process clearing its cache when a key is disabled or deleted.
    """
    query = select(ApiKeyModel).where(ApiKeyModel.access_key == access_key)
    return session.exec(query).first()


@cache(namespace=CacheNamespace.AUTH_INFO, cacheName=CacheName.ASK_INFO, keyExpression="access_key")
async def get_api_key(session: SessionDep, access_key: str) -> ApiKeyModel | None:
    return await get_api_key_uncached(session, access_key)

@clear_cache(namespace=CacheNamespace.AUTH_INFO, cacheName=CacheName.ASK_INFO, keyExpression="access_key")
async def clear_api_key_cache(access_key: str):
     SQLBotLogUtil.info(f"Api key cache for [{access_key}] has been cleaned")