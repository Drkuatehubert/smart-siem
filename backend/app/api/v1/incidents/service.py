from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from app.core.postgres import get_pg_pool
from app.core.pg_utils import serialize_row

logger = logging.getLogger("incidents.service")

_SEVERITY_MAP = {
    "p1": "CRITICAL", "p2": "HIGH", "p3": "WARNING", "p4": "INFO",
    "critical": "CRITICAL", "high": "HIGH", "warning": "WARNING", "info": "INFO",
}

_STATUS_MAP = {
    "open": "open",
    "investigating": "in_progress",
    "in_progress": "in_progress",
    "pending_action": "pending_action",
    "resolved": "resolved",
    "closed": "closed",
}


def _map_severity(s: str) -> str:
    return _SEVERITY_MAP.get(str(s).lower(), "WARNING")

def _map_status(s: str) -> str:
    return _STATUS_MAP.get(str(s).lower(), "open")


async def list_incidents() -> list[dict]:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT i.id, i.title, i.severity::text AS severity,
                      i.status::text AS status, i.opened_at, i.assigned_to,
                      i.alert_id, i.root_cause, i.response_actions,
                      i.affected_assets, i.ioc_indicators, i.lessons_learned,
                      a.title AS alert_title, a.level::text AS alert_level,
                      a.source_ips, a.triggered_at AS alert_triggered_at
               FROM incidents i
               LEFT JOIN alerts a ON i.alert_id = a.id
               ORDER BY i.opened_at DESC LIMIT 50"""
        )
    result = []
    for r in rows:
        d = serialize_row(r)
        if d.get("severity"):
            d["severity"] = d["severity"].lower()
        if d.get("alert_level"):
            d["alert_level"] = d["alert_level"].lower()
        result.append(d)
    return result


async def get_incident(incident_id: str) -> dict | None:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM incidents WHERE id = $1::uuid", incident_id
        )
    return serialize_row(row) if row else None


async def create_incident(data: dict, owner_id: str) -> dict:
    pool = await get_pg_pool()
    titre = data.get("titre") or data.get("title") or "Incident sans titre"
    severity = _map_severity(data.get("priorite") or data.get("severity") or "WARNING")
    alert_id = data.get("alert_id") or None

    async with pool.acquire() as conn:
        # Vérifier que l'alert_id existe en PG avant l'INSERT (FK NOT NULL)
        if alert_id:
            exists = await conn.fetchval(
                "SELECT id FROM alerts WHERE id = $1::uuid", alert_id
            )
            if not exists:
                alert_id = None  # l'alert_id est un ES _id, pas un PG UUID

        if alert_id is None:
            # Pas d'alerte PG liée — insérer sans FK (nécessite que alert_id soit nullable)
            # On utilise la première alerte disponible si besoin (fallback soutenance)
            fallback_alert = await conn.fetchval(
                "SELECT id FROM alerts ORDER BY triggered_at DESC LIMIT 1"
            )
            alert_id = str(fallback_alert) if fallback_alert else None

        if alert_id is None:
            logger.warning("create_incident: aucune alerte PG disponible pour lier l'incident")
            return {"error": "Aucune alerte disponible pour créer un incident"}

        row = await conn.fetchrow(
            """INSERT INTO incidents (alert_id, title, severity, status)
               VALUES ($1::uuid, $2, $3::alert_level, 'open')
               RETURNING *""",
            alert_id, titre, severity,
        )
    return serialize_row(row)


async def update_incident_status(incident_id: str, status: str) -> dict:
    pg_status = _map_status(status)
    resolved_clause = ", resolved_at = NOW()" if pg_status in ("resolved", "closed") else ""
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"""UPDATE incidents
                SET status = $1::incident_status{resolved_clause}
                WHERE id = $2::uuid
                RETURNING *""",
            pg_status, incident_id,
        )
    return serialize_row(row) if row else {"id": incident_id, "status": pg_status}


async def assign_incident(incident_id: str, assigned_to: str) -> dict:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        # Chercher l'utilisateur par username d'abord, puis par UUID
        user_id: str | None = None
        try:
            user_row = await conn.fetchrow(
                "SELECT id FROM users WHERE username = $1", assigned_to
            )
            if user_row:
                user_id = str(user_row["id"])
            else:
                user_row = await conn.fetchrow(
                    "SELECT id FROM users WHERE id = $1::uuid", assigned_to
                )
                if user_row:
                    user_id = str(user_row["id"])
        except Exception:
            pass

        row = await conn.fetchrow(
            """UPDATE incidents
               SET assigned_to = $1::uuid
               WHERE id = $2::uuid
               RETURNING *""",
            user_id, incident_id,
        )
    return serialize_row(row) if row else {"id": incident_id, "assigned_to": assigned_to}


async def add_response_action(incident_id: str, action: str, target: str, by: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    new_entry = json.dumps({
        "action": action,
        "target": target,
        "by": by,
        "at": now,
        "result": "pending",
    })
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """UPDATE incidents
               SET response_actions = response_actions || $1::jsonb
               WHERE id = $2::uuid
               RETURNING *""",
            f"[{new_entry}]", incident_id,
        )
    return serialize_row(row) if row else {"id": incident_id}
