from __future__ import annotations

from app.core.redis_client import get_redis_client


async def get_cache_client():
    # Petit alias de compatibilité : certains modules importent "get_cache_client" depuis
    # core.redis plutôt que "get_redis_client" depuis core.redis_client. Les deux renvoient
    # le même client Redis singleton (voir redis_client.py).
    return get_redis_client()
