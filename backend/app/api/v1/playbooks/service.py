import json as _json
import logging
from typing import Any

from app.core.postgres import get_pg_pool
from app.core.pg_utils import serialize_row

logger = logging.getLogger("playbooks.service")

_JSONB_PLAYBOOK_COLS = ("parameters",)

_SOAR_FALLBACK = [
    {
        "id": "pb-00000000-0001-0000-0000-000000000001",
        "name": "Blocage IP automatique (pfSense)",
        "description": (
            "Bloque automatiquement une adresse IP malveillante sur le pare-feu pfSense "
            "via SSH + paramiko. Commande : pfctl -t blocklist -T add {ip}. "
            "Déclenché sur alerte HIGH/CRITICAL contenant un source_ip."
        ),
        "action_type": "block_ip",
        "execution_mode": "AUTO",
        "parameters": {
            "method": "pfSense SSH (paramiko)",
            "command": "pfctl -t blocklist -T add {ip}",
            "trigger": "HIGH/CRITICAL avec source_ip",
            "firewall_host": "192.168.100.1",
        },
        "target_type": "ip_address",
        "confirmation_timeout_seconds": 0,
        "is_active": True,
        "execution_count": 0,
        "last_executed_at": None,
        "created_by": "system",
    },
    {
        "id": "pb-00000000-0002-0000-0000-000000000002",
        "name": "Désactivation compte Active Directory (LDAP)",
        "description": (
            "Désactive un compte utilisateur compromis via LDAP3 sur le contrôleur de domaine "
            "(port 389). Mode CONFIRM : un analyste doit valider dans les 60 secondes. "
            "Déclenché sur détection de compromission de compte."
        ),
        "action_type": "disable_account",
        "execution_mode": "CONFIRM",
        "parameters": {
            "method": "LDAP3 disable_account",
            "ldap_port": 389,
            "trigger": "Compromission compte détectée",
            "timeout_confirmation_s": 60,
        },
        "target_type": "user_account",
        "confirmation_timeout_seconds": 60,
        "is_active": True,
        "execution_count": 0,
        "last_executed_at": None,
        "created_by": "system",
    },
    {
        "id": "pb-00000000-0003-0000-0000-000000000003",
        "name": "Escalade incident — Alerte critique non résolue",
        "description": (
            "Crée un ticket d'incident et envoie une notification d'escalade immédiate "
            "quand une alerte CRITICAL reste non résolue au-delà du seuil configuré. "
            "Déclenché automatiquement par le moteur de corrélation."
        ),
        "action_type": "notify_escalation",
        "execution_mode": "CONFIRM",
        "parameters": {
            "method": "notification + ticket ITSM",
            "trigger": "Alerte CRITICAL non résolue",
            "channels": ["email", "slack"],
            "ticket_system": "interne",
        },
        "target_type": None,
        "confirmation_timeout_seconds": 300,
        "is_active": True,
        "execution_count": 0,
        "last_executed_at": None,
        "created_by": "system",
    },
]


def _fix_jsonb(d: dict) -> dict:
    for key in _JSONB_PLAYBOOK_COLS:
        v = d.get(key)
        if isinstance(v, str):
            try:
                d[key] = _json.loads(v)
            except Exception:
                d[key] = {}
    return d


async def list_playbooks() -> list[dict]:
    try:
        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT * FROM playbooks ORDER BY name ASC")
        if rows:
            return [_fix_jsonb(serialize_row(r)) for r in rows]
    except Exception:
        pass
    return _SOAR_FALLBACK


async def get_playbook_by_id(playbook_id: str) -> dict | None:
    # Chercher dans les playbooks hardcodés en premier
    for pb in _SOAR_FALLBACK:
        if pb["id"] == playbook_id:
            return pb

    # Puis dans PostgreSQL
    try:
        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM playbooks WHERE id = $1::uuid", playbook_id
            )
        if row:
            return _fix_jsonb(serialize_row(row))
    except Exception as exc:
        logger.warning("get_playbook_by_id PG échoué : %s", exc)

    return None


async def create_playbook(data: dict[str, Any]) -> dict:
    """Insère un nouveau playbook dans PostgreSQL et retourne la ligne créée."""
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO playbooks
               (name, description, action_type, execution_mode,
                parameters, target_type, confirmation_timeout_seconds,
                rollback_supported, is_active)
               VALUES ($1, $2, $3, $4::exec_mode,
                       $5::jsonb, $6, $7, $8, $9)
               RETURNING *""",
            data["name"],
            data.get("description", ""),
            data["action_type"],
            data.get("execution_mode", "CONFIRM"),
            _json.dumps(data.get("parameters", {})),
            data.get("target_type") or None,
            max(1, int(data.get("confirmation_timeout_seconds", 300))),
            bool(data.get("rollback_supported", False)),
            bool(data.get("is_active", True)),
        )
    return _fix_jsonb(serialize_row(row))


async def trigger_playbook(playbook_id: str, triggered_by: str) -> dict:
    """Enregistre une exécution de playbook et retourne le statut."""
    pb = await get_playbook_by_id(playbook_id)
    if pb is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Playbook introuvable")

    execution_mode = pb.get("execution_mode", "CONFIRM")

    # Log de l'exécution en PG si possible
    try:
        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO playbook_executions
                   (playbook_id, triggered_by, execution_mode, target_value, status)
                   VALUES ($1::uuid, $2::uuid, $3::exec_mode, 'manual', 'pending')""",
                playbook_id, triggered_by, execution_mode,
            )
    except Exception as exc:
        logger.warning("Enregistrement exécution playbook PG échoué (non bloquant) : %s", exc)

    return {
        "playbook_id":     playbook_id,
        "playbook_name":   pb.get("name"),
        "execution_mode":  execution_mode,
        "status":          "awaiting_confirm" if execution_mode == "CONFIRM" else "triggered",
    }
