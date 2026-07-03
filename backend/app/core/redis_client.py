from __future__ import annotations

import json
import logging
from typing import Optional

import redis.asyncio as aioredis

from app.config import settings

logger = logging.getLogger("redis")
_redis_client: Optional[aioredis.Redis] = None


def get_redis_client() -> aioredis.Redis:
    """Singleton du client Redis (async)."""
    global _redis_client
    if _redis_client is None:
        scheme = "rediss" if settings.REDIS_TLS else "redis"
        auth = f":{settings.REDIS_PASSWORD}@" if settings.REDIS_PASSWORD else ""
        url = f"{scheme}://{auth}{settings.REDIS_HOST}:{settings.REDIS_PORT}/0"
        _redis_client = aioredis.from_url(
            url,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
            health_check_interval=30,
        )
    return _redis_client


async def close_redis_client() -> None:
    global _redis_client
    if _redis_client is not None:
        try:
            await _redis_client.aclose()
        except Exception:
            pass
        _redis_client = None


async def publish_log(log: dict) -> None:
    """Publie un log brut dans le stream Redis (XADD avec MAXLEN).
    Lève si le message dépasse REDIS_MESSAGE_MAX_BYTES (anti-DoS).
    """
    payload = json.dumps(log, ensure_ascii=False)
    if len(payload.encode("utf-8")) > settings.REDIS_MESSAGE_MAX_BYTES:
        raise ValueError(
            f"Log trop volumineux (>{settings.REDIS_MESSAGE_MAX_BYTES} octets)"
        )
    r = get_redis_client()
    await r.xadd(
        settings.REDIS_STREAM_KEY,
        {"data": payload},
        maxlen=settings.REDIS_STREAM_MAXLEN,
        approximate=True,
    )
