from app.core.postgres import get_pg_pool
from app.core.pg_utils import serialize_row


async def list_profiles() -> list[dict]:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM ueba_profiles ORDER BY risk_score_current DESC"
        )
    return [serialize_row(r) for r in rows]
