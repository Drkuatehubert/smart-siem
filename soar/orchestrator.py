import asyncio
import logging

from soar.playbooks.playbook_1_block_ip import Playbook1BlockIP
from soar.playbooks.playbook_2_disable_account import Playbook2DisableAccount
from soar.playbooks.playbook_3_escalate import Playbook3Escalate

logger = logging.getLogger(__name__)

_BRUTE_FORCE_RULES = {"brute_force_ssh", "brute_force_rdp", "port_scan", "T1110", "T1046"}
_EXFIL_RULES = {"exfiltration", "dormant_account", "ueba_critical", "T1041", "T1078"}

# IPs que l'on ne bloque jamais (loopback, SIEM interne, non-routable)
_BLOCKED_PREFIXES = ("127.", "0.", "169.254.")
_BLOCKED_IPS = {"0.0.0.0", "::1"}


def _is_safe_to_block(ip: str) -> bool:
    """Retourne False si l'IP est loopback, APIPA ou non-routable."""
    if not ip:
        return False
    if ip in _BLOCKED_IPS:
        return False
    for prefix in _BLOCKED_PREFIXES:
        if ip.startswith(prefix):
            return False
    return True


async def handle_alert(alert: dict) -> dict:
    """
    Point d'entrée principal du SOAR.
    Reçoit une alerte normalisée et exécute le bon playbook.

    Structure d'alerte attendue :
    {
        "id": "uuid",
        "rule_id": "brute_force_ssh",
        "severity": "HIGH",
        "source_ip": "192.168.200.100",
        "username": "jean",
        "description": "..."
    }
    """
    alert_id = alert.get("alert_id", alert.get("id", "unknown"))
    rule_id = alert.get("rule_id", "")
    severity = alert.get("level", alert.get("severity", "INFO"))

    logger.info(
        "Orchestrateur — alerte reçue : id=%s rule=%s severity=%s",
        alert_id, rule_id, severity,
    )

    resultats = []

    # Playbook 3 — Toujours notifier sur HIGH et CRITICAL
    if severity in {"HIGH", "CRITICAL"}:
        r3 = await Playbook3Escalate().execute(alert)
        resultats.append(r3)

    # Playbook 1 — Blocage IP sur brute-force et scan
    rule_key = rule_id or alert.get("rule_name", "")
    if rule_key in _BRUTE_FORCE_RULES or "T1110" in rule_key or "brute" in rule_key.lower() or "Brute" in rule_key:
        source_ips = alert.get("source_ips", [])
        ip_to_block = alert.get("source_ip") or (source_ips[0] if source_ips else "")
        if not _is_safe_to_block(ip_to_block):
            logger.warning("Playbook1 ignoré — IP non bloquable : %s", ip_to_block)
            resultats.append({"status": "skipped", "reason": "IP loopback ignorée", "ip": ip_to_block})
        else:
            r1 = await Playbook1BlockIP().execute(alert)
            resultats.append(r1)

    # Playbook 2 — Désactivation compte sur exfiltration et UEBA
    if rule_id in _EXFIL_RULES:
        r2 = await Playbook2DisableAccount().execute(alert)
        resultats.append(r2)

    result = {"alert_id": alert_id, "playbooks_executed": resultats}
    logger.info("Orchestrateur — résultat : %s", result)
    return result


async def cancel_playbook(alert_id: str) -> dict:
    """Annuler un playbook en mode CONFIRM avant qu'il s'exécute."""
    from soar import config
    config.CANCELLED_ALERTS.add(alert_id)
    logger.info("Annulation enregistrée pour alert_id=%s", alert_id)
    return {"status": "cancelled", "alert_id": alert_id}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s — %(message)s")

    asyncio.run(handle_alert({
        "id": "test-001",
        "rule_id": "brute_force_ssh",
        "severity": "HIGH",
        "source_ip": "192.168.200.100",
        "description": "5 échecs SSH en 60s",
    }))

    asyncio.run(handle_alert({
        "id": "test-002",
        "rule_id": "exfiltration",
        "severity": "CRITICAL",
        "username": "jean",
        "source_ip": "192.168.200.100",
        "description": "Exfiltration détectée - score UEBA 80",
    }))
