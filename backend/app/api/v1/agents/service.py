import json
import logging
from datetime import datetime, timezone

from app.core.postgres import get_pg_pool
from app.core.pg_utils import serialize_row

logger = logging.getLogger("agents.service")

_STATIC_AGENTS = [
    {"id": "agent-ubuntu",  "host": "192.168.100.128", "os": "Ubuntu",  "status": "offline"},
    {"id": "agent-windows", "host": "192.168.100.129", "os": "Windows", "status": "offline"},
]


def _agent_status(last_seen_iso: str) -> str:
    """Retourne 'active' si last_seen < 5 min, sinon 'offline'."""
    try:
        dt = datetime.fromisoformat(last_seen_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return "active" if (datetime.now(timezone.utc) - dt).total_seconds() < 300 else "offline"
    except Exception:
        return "offline"


async def _list_agents_from_redis() -> list[dict] | None:
    """Lit les clés agent:* depuis Redis et calcule le statut dynamiquement."""
    try:
        from app.core.redis_client import get_redis_client
        r = get_redis_client()
        keys = await r.keys("agent:*")
        if not keys:
            return None
        now = datetime.now(timezone.utc).isoformat()
        agents = []
        for key in keys:
            raw = await r.get(key)
            if not raw:
                continue
            data = json.loads(raw)
            host = data.get("host", "unknown")
            last_seen = data.get("last_seen", now)
            agents.append({
                "id":        f"agent-{host}",
                "host":      data.get("ip") or host,
                "os":        data.get("os", "Unknown"),
                "status":    _agent_status(last_seen),
                "last_seen": last_seen,
                "hostname":  host,
            })
        logger.info("Redis agents : %d agents trouvés", len(agents))
        return agents
    except Exception as exc:
        logger.warning("Redis agent lookup failed: %s", exc)
        return None


async def list_agents() -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()

    # 1. PG log_sources (source autoritaire si peuplée)
    try:
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
                agents.append({
                    "id":        str(data.get("id")),
                    "host":      data.get("ip_address") or data.get("hostname") or data.get("name"),
                    "os":        (data.get("metadata") or {}).get("os") or data.get("source_type") or "Unknown",
                    "status":    "active" if data.get("is_active") else "inactive",
                    "last_seen": data.get("last_seen_at") or now,
                    "hostname":  data.get("hostname") or data.get("name"),
                })
            return agents
    except Exception as exc:
        logger.warning("PG agent lookup failed: %s", exc)

    # 2. Redis agent:* — statut calculé depuis le heartbeat du normalizer
    redis_agents = await _list_agents_from_redis()
    if redis_agents:
        return redis_agents

    # 3. Fallback statique (aucun agent n'a encore envoyé de logs)
    return [{**agent, "last_seen": now} for agent in _STATIC_AGENTS]
