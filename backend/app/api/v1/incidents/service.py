from __future__ import annotations

from datetime import datetime, timezone

from app.core.elasticsearch import get_es_client
from app.core.postgres import get_pg_pool
from app.core.pg_utils import serialize_row


async def list_incidents() -> list[dict]:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM incidents ORDER BY opened_at DESC")
    return [serialize_row(r) for r in rows]


async def create_incident(data: dict, owner_id: str):
    # owner_id vient toujours de l'utilisateur authentifié courant (voir router.py),
    # jamais d'un champ fourni par le client, pour éviter qu'on s'attribue un incident à un tiers.
    es = get_es_client()
    now = datetime.now(timezone.utc).isoformat()
    doc = {**data, "owner": owner_id, "created_at": now, "updated_at": now}
    res = await es.index(index="idx-incidents", document=doc)
    return {"id": res["_id"], **doc}
