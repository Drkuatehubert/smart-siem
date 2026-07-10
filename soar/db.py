"""soar/db.py — Connexion PostgreSQL légère pour le soar-worker."""
import logging

import asyncpg

from soar.config import PG_DSN

logger = logging.getLogger("soar.db")

_pool: asyncpg.Pool | None = None

_BLOCK_IP_UUID = "00000001-0000-0001-0000-000000000001"
_DISABLE_ACCOUNT_UUID = "00000001-0000-0002-0000-000000000001"
_ESCALATE_UUID = "00000001-0000-0003-0000-000000000001"

_SYSTEM_PLAYBOOKS = [
    {
        "id": _BLOCK_IP_UUID,
        "name": "Blocage IP automatique (pfSense)",
        "description": "Bloque l'IP source malveillante via pfSense SSH (pfctl -t blocklist -T add).",
        "action_type": "block_ip",
        "execution_mode": "AUTO",
        "parameters": '{"method": "pfSense SSH", "command": "pfctl -t blocklist -T add {ip}"}',
        "confirmation_timeout_seconds": 1,
    },
    {
        "id": _DISABLE_ACCOUNT_UUID,
        "name": "Désactivation compte Active Directory (LDAP)",
        "description": "Désactive un compte AD compromis via LDAP3 (userAccountControl = 514).",
        "action_type": "disable_account",
        "execution_mode": "CONFIRM",
        "parameters": '{"method": "LDAP3 disable_account", "ldap_port": 389}',
        "confirmation_timeout_seconds": 60,
    },
    {
        "id": _ESCALATE_UUID,
        "name": "Escalade incident critique",
        "description": "Cree un ticket et notifie quand une alerte CRITICAL reste non resolue.",
        "action_type": "notify_escalation",
        "execution_mode": "AUTO",
        "parameters": '{"channels": ["email"], "ticket_system": "interne", "trigger": "CRITICAL non resolu"}',
        "confirmation_timeout_seconds": 1,
    },
]


async def get_pg() -> asyncpg.Pool | None:
    global _pool
    if not PG_DSN:
        logger.warning("PG_DSN non configuré — persistance SOAR désactivée")
        return None
    if _pool is None:
        try:
            _pool = await asyncpg.create_pool(PG_DSN, min_size=1, max_size=3)
            logger.info("Pool PostgreSQL SOAR créé")
            await _seed_system_playbooks(_pool)
        except Exception as exc:
            logger.error("Impossible de créer le pool PG : %s", exc)
            return None
    return _pool


async def _seed_system_playbooks(pool: asyncpg.Pool) -> None:
    """Insère les playbooks système si absents (ON CONFLICT DO NOTHING)."""
    async with pool.acquire() as conn:
        for pb in _SYSTEM_PLAYBOOKS:
            try:
                await conn.execute(
                    """INSERT INTO playbooks
                       (id, name, description, action_type, execution_mode,
                        parameters, confirmation_timeout_seconds)
                       VALUES ($1::uuid, $2, $3, $4, $5::exec_mode, $6::jsonb, $7)
                       ON CONFLICT DO NOTHING""",
                    pb["id"], pb["name"], pb["description"],
                    pb["action_type"], pb["execution_mode"],
                    pb["parameters"], pb["confirmation_timeout_seconds"],
                )
            except Exception as exc:
                logger.warning("Seed playbook '%s' échoué (non bloquant) : %s", pb["name"], exc)


async def increment_execution_count(playbook_id: str) -> None:
    """Met à jour execution_count + last_executed_at après une exécution réussie."""
    pool = await get_pg()
    if not pool:
        return
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """UPDATE playbooks
                   SET execution_count = execution_count + 1,
                       last_executed_at = NOW()
                   WHERE id = $1::uuid""",
                playbook_id,
            )
    except Exception as exc:
        logger.warning("increment_execution_count PG échoué : %s", exc)


async def save_playbook_execution(
    *,
    playbook_id: str,
    execution_mode: str,
    target_value: str,
    result: dict,
    parameters_used: dict,
    alert_id: str | None = None,
    status: str = "success",
) -> None:
    """Insère une ligne dans playbook_executions. Non bloquant en cas d'erreur."""
    import json

    valid_statuses = {"pending", "awaiting_confirm", "running", "success", "failed", "cancelled", "rolled_back"}
    pg_status = status if status in valid_statuses else "success"

    pool = await get_pg()
    if not pool:
        return

    try:
        async with pool.acquire() as conn:
            # Vérifier que alert_id est un UUID valide et existe dans alerts
            pg_alert_id = None
            if alert_id:
                try:
                    exists = await conn.fetchval(
                        "SELECT 1 FROM alerts WHERE id = $1::uuid", alert_id
                    )
                    if exists:
                        pg_alert_id = alert_id
                except Exception:
                    pass

            await conn.execute(
                """INSERT INTO playbook_executions
                   (playbook_id, execution_mode, target_value, status,
                    result, parameters_used, alert_id, completed_at)
                   VALUES ($1::uuid, $2::exec_mode, $3, $4,
                           $5::jsonb, $6::jsonb,
                           $7::uuid, NOW())""",
                playbook_id, execution_mode, target_value, pg_status,
                json.dumps(result), json.dumps(parameters_used),
                pg_alert_id,
            )
            logger.info("Exécution SOAR sauvegardée : %s → %s [%s]", playbook_id, target_value, pg_status)
        if pg_status == "success":
            await increment_execution_count(playbook_id)
    except Exception as exc:
        logger.warning("save_playbook_execution PG échoué (non bloquant) : %s", exc)
