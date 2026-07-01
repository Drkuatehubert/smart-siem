"""
playbook/services.py

execute_playbook() est appelé :
  1. Manuellement → via le controller POST /playbooks/execute
  2. Automatiquement → via alert_worker.py quand une alerte non traitée est détectée
"""
import asyncio
import httpx
from uuid import UUID, uuid4
from datetime import datetime
from app.core.database import get_pool
from app.core.rbac import CurrentUser
from app.playbook.models import ExecutePlaybookRequest, PlaybookType, PlaybookStatus
from app.config import settings


async def execute_playbook(
    req: ExecutePlaybookRequest,
    user: CurrentUser | None = None,   # None si appelé automatiquement par le worker
    triggered_by: str = "auto"
) -> dict:
    """
    Exécute un playbook selon son type.
    Enregistre l'exécution dans playbook_executions (PostgreSQL).
    Met à jour le statut de l'alerte en 'investigating'.
    """
    pool = await get_pool()

    # Récupère le type du playbook
    async with pool.acquire() as conn:
        pb = await conn.fetchrow(
            "SELECT id, name, playbook_type FROM playbooks WHERE id = $1",
            req.playbook_id
        )
    if not pb:
        raise ValueError(f"Playbook {req.playbook_id} introuvable")

    execution_id = uuid4()
    started_at   = datetime.utcnow()

    # Crée l'enregistrement d'exécution en état PENDING
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO playbook_executions
                (id, playbook_id, alert_id, status, triggered_by,
                 triggered_by_user_id, started_at, params)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            execution_id,
            req.playbook_id,
            req.alert_id,
            PlaybookStatus.RUNNING.value,
            triggered_by,
            str(user.user_id) if user else None,
            started_at,
            req.json()
        )

        # Met l'alerte en 'investigating'
        await conn.execute(
            "UPDATE alerts SET status = 'investigating', updated_at = NOW() WHERE id = $1",
            req.alert_id
        )

    # Exécution selon le type
    try:
        result = await _dispatch(pb["playbook_type"], req)
        status = PlaybookStatus.SUCCESS
    except Exception as e:
        result = {"error": str(e)}
        status = PlaybookStatus.FAILED

    # Met à jour l'exécution avec le résultat
    finished_at = datetime.utcnow()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE playbook_executions
            SET status = $1, result = $2, finished_at = $3
            WHERE id = $4
            """,
            status.value, str(result), finished_at, execution_id
        )

    return {
        "execution_id": str(execution_id),
        "status":       status.value,
        "result":       result,
        "duration_ms":  int((finished_at - started_at).total_seconds() * 1000)
    }


async def _dispatch(playbook_type: str, req: ExecutePlaybookRequest) -> dict:
    """Route vers la bonne action selon le type de playbook."""
    match playbook_type:
        case PlaybookType.BLOCK_IP:
            return await _block_ip(req.block_ip_params)
        case PlaybookType.DISABLE_ACCOUNT:
            return await _disable_account(req.disable_account_params)
        case PlaybookType.ESCALATE:
            return await _escalate(req.escalate_params, req.alert_id)
        case PlaybookType.ISOLATE_MACHINE:
            return await _isolate_machine(req.isolate_machine_params)
        case _:
            raise ValueError(f"Type de playbook inconnu : {playbook_type}")


async def _block_ip(params) -> dict:
    """
    Envoie une commande de blocage IP vers le firewall/IPS.
    En prod : appel API firewall (Palo Alto, pfSense, iptables remote...)
    """
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{settings.FIREWALL_API_URL}/block",
            json={
                "ip":           params.ip_address,
                "duration_hours": params.duration_hours
            },
            headers={"Authorization": f"Bearer {settings.FIREWALL_API_KEY}"},
            timeout=10.0
        )
        resp.raise_for_status()
    return {"blocked_ip": params.ip_address, "duration_hours": params.duration_hours}


async def _disable_account(params) -> dict:
    """Désactive un compte dans l'annuaire (simulation LDAP/AD)."""
    # En prod : python-ldap ou appel API AD
    return {"disabled_user": params.username, "reason": params.reason}


async def _escalate(params, alert_id: UUID) -> dict:
    """Envoie une notification d'escalade par email/webhook."""
    async with httpx.AsyncClient() as client:
        await client.post(
            settings.WEBHOOK_URL,
            json={
                "text":     f"🚨 ESCALADE — Alerte {alert_id} nécessite attention immédiate",
                "to":       params.escalate_to,
                "message":  params.message
            }
        )
    return {"escalated_to": params.escalate_to}


async def _isolate_machine(params) -> dict:
    """Isole une machine du réseau (appel agent ou API réseau)."""
    return {"isolated_host": params.hostname}