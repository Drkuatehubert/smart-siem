"""soar/router.py — Gestion des actions SOAR (IPs bloquées, comptes désactivés, historique)."""
import asyncio
import json
import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.postgres import get_pg_pool
from app.core.rbac import require_any_role

logger = logging.getLogger("soar.management")

router = APIRouter(tags=["SOAR Management"])

# Credentials pfSense (injectés via .env / docker-compose)
_PFSENSE_HOST = os.getenv("PFSENSE_HOST", "")
_PFSENSE_PORT = int(os.getenv("PFSENSE_PORT", "22"))
_PFSENSE_USER = os.getenv("PFSENSE_USER", "admin")
_PFSENSE_PASS = os.getenv("PFSENSE_PASSWORD", "")

# Credentials AD
_AD_HOST = os.getenv("AD_HOST", "")
_AD_PORT = int(os.getenv("AD_PORT", "389"))
_AD_USER = os.getenv("AD_USER", "")
_AD_PASS = os.getenv("AD_PASSWORD", "")
_AD_BASE_DN = os.getenv("AD_BASE_DN", "")
_AD_TARGET_OU = os.getenv("AD_TARGET_OU", "")

_PB_BLOCK_IP_ID     = "00000001-0000-0001-0000-000000000001"
_PB_DISABLE_ACCT_ID = "00000001-0000-0002-0000-000000000001"


# ── Pydantic request bodies ───────────────────────────────────────────────────

class BlockIpBody(BaseModel):
    ip: str

class DisableAccountBody(BaseModel):
    username: str


# ── Helpers sync (exécutés dans un thread) ────────────────────────────────────

def _pfsense_block(ip: str) -> None:
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=_PFSENSE_HOST, port=_PFSENSE_PORT,
        username=_PFSENSE_USER, password=_PFSENSE_PASS,
        timeout=10, look_for_keys=False, allow_agent=False,
    )
    try:
        _, stdout, stderr = client.exec_command(
            f"pfctl -t blocklist -T add {ip}", timeout=15
        )
        err = stderr.read().decode().strip()
        if err:
            logger.warning("pfSense block stderr : %s", err)
    finally:
        client.close()


def _pfsense_unblock(ip: str) -> None:
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=_PFSENSE_HOST, port=_PFSENSE_PORT,
        username=_PFSENSE_USER, password=_PFSENSE_PASS,
        timeout=10, look_for_keys=False, allow_agent=False,
    )
    try:
        _, stdout, stderr = client.exec_command(
            f"pfctl -t blocklist -T delete {ip}", timeout=15
        )
        err = stderr.read().decode().strip()
        if err:
            logger.warning("pfSense unblock stderr : %s", err)
    finally:
        client.close()


def _ad_disable(username: str) -> None:
    from ldap3 import Connection, MODIFY_REPLACE, SUBTREE, Server as LdapServer
    UAC_DISABLED = 514
    server = LdapServer(_AD_HOST, port=_AD_PORT, use_ssl=False, connect_timeout=5)
    conn = Connection(
        server, user=_AD_USER, password=_AD_PASS,
        auto_bind=True, raise_exceptions=True,
    )
    try:
        search_base = _AD_TARGET_OU or _AD_BASE_DN
        conn.search(
            search_base=search_base,
            search_filter=f"(sAMAccountName={username})",
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
        )
        if not conn.entries:
            raise ValueError(f"Compte '{username}' introuvable dans l'AD ({search_base})")
        dn = str(conn.entries[0].distinguishedName)
        conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [UAC_DISABLED])]})
        if conn.result["result"] != 0:
            raise ValueError(conn.result.get("description", "erreur LDAP inconnue"))
    finally:
        conn.unbind()


def _ad_enable(username: str) -> None:
    from ldap3 import Connection, MODIFY_REPLACE, SUBTREE, Server as LdapServer
    UAC_ENABLED = 512
    server = LdapServer(_AD_HOST, port=_AD_PORT, use_ssl=False, connect_timeout=5)
    conn = Connection(
        server, user=_AD_USER, password=_AD_PASS,
        auto_bind=True, raise_exceptions=True,
    )
    try:
        search_base = _AD_TARGET_OU or _AD_BASE_DN
        conn.search(
            search_base=search_base,
            search_filter=f"(sAMAccountName={username})",
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
        )
        if not conn.entries:
            raise ValueError(f"Compte '{username}' introuvable dans l'AD ({search_base})")
        dn = str(conn.entries[0].distinguishedName)
        conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [UAC_ENABLED])]})
        if conn.result["result"] != 0:
            raise ValueError(conn.result.get("description", "erreur LDAP inconnue"))
    finally:
        conn.unbind()


# ── Helper PG ────────────────────────────────────────────────────────────────

async def _log_soar_action(action: str, target: str, params: dict) -> None:
    try:
        pool = await get_pg_pool()
        pb_id = _PB_BLOCK_IP_ID if "ip" in action else _PB_DISABLE_ACCT_ID
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO playbook_executions
                   (playbook_id, execution_mode, target_value, status, result, parameters_used)
                   VALUES ($1::uuid, 'AUTO'::exec_mode, $2, 'success', $3::jsonb, $4::jsonb)""",
                pb_id, target,
                json.dumps({"action": action, "target": target}),
                json.dumps(params),
            )
    except Exception as exc:
        logger.warning("_log_soar_action PG échoué (non bloquant) : %s", exc)


def _row_to_dict(r, *, blocked_ip_col: str = "blocked_ip") -> dict:
    params = r["parameters_used"] or {}
    if isinstance(params, str):
        try:
            params = json.loads(params)
        except Exception:
            params = {}
    return {
        "id":          str(r["id"]),
        "alert_id":    str(r["alert_id"]) if r["alert_id"] else None,
        blocked_ip_col: r["target_value"],
        "executed_at": r["executed_at"].isoformat() if r["executed_at"] else None,
        "metadata":    params,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/history", summary="Historique complet des actions SOAR")
async def get_soar_history(_=Depends(require_any_role)):
    try:
        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT pe.id, pe.target_value, pe.status, pe.started_at,
                       pe.alert_id,
                       COALESCE(pe.result->>'action', p.action_type) AS action,
                       p.name AS playbook_name
                FROM playbook_executions pe
                JOIN playbooks p ON pe.playbook_id = p.id
                ORDER BY pe.started_at DESC
                LIMIT 200
            """)
    except Exception as exc:
        logger.error("get_soar_history PG : %s", exc)
        return []

    return [
        {
            "id":            str(r["id"]),
            "action":        r["action"],
            "playbook_name": r["playbook_name"],
            "target":        r["target_value"],
            "status":        r["status"],
            "alert_id":      str(r["alert_id"]) if r["alert_id"] else None,
            "executed_at":   r["started_at"].isoformat() if r["started_at"] else None,
        }
        for r in rows
    ]


@router.post("/block-ip", summary="Bloquer manuellement une IP sur pfSense")
async def block_ip_route(body: BlockIpBody, _=Depends(require_any_role)):
    ip = body.ip.strip()
    if not ip:
        raise HTTPException(status_code=422, detail="IP manquante")
    if not _PFSENSE_HOST:
        raise HTTPException(status_code=503, detail="PFSENSE_HOST non configuré")
    try:
        await asyncio.to_thread(_pfsense_block, ip)
    except Exception as exc:
        logger.error("Erreur blocage IP %s : %s", ip, exc)
        raise HTTPException(status_code=500, detail=f"Erreur pfSense : {exc}")

    await _log_soar_action("block_ip", ip, {"ip": ip, "firewall": "pfSense", "source": "manuel"})
    return {"status": "blocked", "ip": ip}


@router.post("/disable-account", summary="Désactiver manuellement un compte AD")
async def disable_account_route(body: DisableAccountBody, _=Depends(require_any_role)):
    username = body.username.strip()
    if not username:
        raise HTTPException(status_code=422, detail="Username manquant")
    if not _AD_HOST:
        raise HTTPException(status_code=503, detail="AD_HOST non configuré")
    try:
        await asyncio.to_thread(_ad_disable, username)
    except Exception as exc:
        logger.error("Erreur désactivation %s : %s", username, exc)
        raise HTTPException(status_code=500, detail=f"Erreur AD : {exc}")

    await _log_soar_action(
        "disable_account", username,
        {"username": username, "domain": "ctu.local", "source": "manuel"},
    )
    return {"status": "disabled", "username": username}


@router.get("/blocked-ips", summary="Liste des IPs bloquées par SOAR")
async def get_blocked_ips(_=Depends(require_any_role)):
    try:
        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT pe.id, pe.alert_id, pe.target_value, pe.started_at AS executed_at,
                       pe.parameters_used
                FROM playbook_executions pe
                JOIN playbooks p ON pe.playbook_id = p.id
                WHERE p.action_type = 'block_ip'
                  AND COALESCE(pe.result->>'action', 'block_ip') = 'block_ip'
                  AND pe.status = 'success'
                ORDER BY pe.started_at DESC
                LIMIT 100
            """)
    except Exception as exc:
        logger.error("get_blocked_ips PG : %s", exc)
        return []

    return [
        {**_row_to_dict(r, blocked_ip_col="blocked_ip"), "firewall": "pfSense"}
        for r in rows
    ]


@router.delete("/blocked-ips/{ip}", summary="Débloquer une IP sur pfSense")
async def unblock_ip_route(ip: str, _=Depends(require_any_role)):
    if not _PFSENSE_HOST:
        raise HTTPException(status_code=503, detail="PFSENSE_HOST non configuré")
    try:
        await asyncio.to_thread(_pfsense_unblock, ip)
    except Exception as exc:
        logger.error("Erreur déblocage IP %s : %s", ip, exc)
        raise HTTPException(status_code=500, detail=f"Erreur pfSense : {exc}")

    await _log_soar_action("unblock_ip", ip, {"ip": ip, "firewall": "pfSense"})
    return {"status": "unblocked", "ip": ip}


@router.get("/disabled-accounts", summary="Liste des comptes désactivés par SOAR")
async def get_disabled_accounts(_=Depends(require_any_role)):
    try:
        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT pe.id, pe.alert_id, pe.target_value, pe.started_at AS executed_at,
                       pe.parameters_used
                FROM playbook_executions pe
                JOIN playbooks p ON pe.playbook_id = p.id
                WHERE p.action_type = 'disable_account'
                  AND COALESCE(pe.result->>'action', 'disable_account') = 'disable_account'
                  AND pe.status = 'success'
                ORDER BY pe.started_at DESC
                LIMIT 100
            """)
    except Exception as exc:
        logger.error("get_disabled_accounts PG : %s", exc)
        return []

    results = []
    for r in rows:
        d = _row_to_dict(r, blocked_ip_col="username")
        d["domain"] = d["metadata"].get("domain", "ctu.local")
        results.append(d)
    return results


@router.post("/disabled-accounts/{username}/enable", summary="Réactiver un compte AD")
async def enable_account_route(username: str, _=Depends(require_any_role)):
    if not _AD_HOST:
        raise HTTPException(status_code=503, detail="AD_HOST non configuré")
    try:
        await asyncio.to_thread(_ad_enable, username)
    except Exception as exc:
        logger.error("Erreur réactivation %s : %s", username, exc)
        raise HTTPException(status_code=500, detail=f"Erreur AD : {exc}")

    await _log_soar_action(
        "enable_account", username,
        {"username": username, "domain": "ctu.local"},
    )
    return {"status": "enabled", "username": username}
