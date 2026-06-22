"""redis_client.py — Client Redis Streams"""
import redis.asyncio as aioredis
from app.config import settings

_redis_client = None

def get_redis_client():
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(
            f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}",
            decode_responses=True
        )
    return _redis_client

async def publish_log(log: dict) -> None:
    """Publie un log brut dans Redis Streams."""
    import json
    r = get_redis_client()
    await r.xadd(settings.REDIS_STREAM_KEY, {"data": json.dumps(log)})
