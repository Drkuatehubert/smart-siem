from app.core.postgres import get_pg_pool
from app.core.pg_utils import serialize_row


async def list_playbooks() -> list[dict]:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT * FROM playbooks ORDER BY name ASC"""
        )
    return [serialize_row(r) for r in rows]
