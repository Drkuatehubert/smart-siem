from datetime import datetime, timezone

from app.core.postgres import get_pg_pool
from app.core.pg_utils import serialize_row


_STATIC_AGENTS = [
    {
        "id": "agent-ubuntu",
        "host": "192.168.100.128",
        "os": "Ubuntu",
        "status": "active",
    },
    {
        "id": "agent-windows",
        "host": "192.168.100.129",
        "os": "Windows",
        "status": "active",
    },
]


async def list_agents() -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id, name, ip_address, hostname, source_type,
                      is_active, last_seen_at, metadata
               FROM log_sources
               ORDER BY last_seen_at DESC NULLS LAST"""
        )

    if rows:
        agents = []
        for row in rows:
            data = serialize_row(row)
            agents.append(
                {
                    "id": str(data.get("id")),
                    "host": data.get("ip_address") or data.get("hostname") or data.get("name"),
                    "os": (data.get("metadata") or {}).get("os") or data.get("source_type") or "Unknown",
                    "status": "active" if data.get("is_active") else "inactive",
                    "last_seen": data.get("last_seen_at") or now,
                    "hostname": data.get("hostname") or data.get("name"),
                    "name": data.get("name"),
                    "source_type": data.get("source_type"),
                }
            )
        return agents

    return [
        {**agent, "last_seen": now}
        for agent in _STATIC_AGENTS
    ]
