import asyncio
import logging

from soar import config
from soar.clients.pfsense_client import PfSenseClient
from soar.db import save_playbook_execution
from soar.playbooks.base_playbook import BasePlaybook

logger = logging.getLogger(__name__)

_PLAYBOOK_ID = "00000001-0000-0001-0000-000000000001"


class Playbook1BlockIP(BasePlaybook):
    async def execute(self, alert: dict) -> dict:
        source_ips = alert.get("source_ips", [])
        ip = alert.get("source_ip") or (source_ips[0] if source_ips else None) or alert.get("normalized_fields", {}).get("source_ip")
        if not ip:
            return {"status": "skipped", "reason": "no source_ip"}

        alert_id = alert.get("alert_id") or alert.get("pg_alert_id")

        try:
            client = PfSenseClient()
            await asyncio.to_thread(client.connect)
            try:
                await asyncio.to_thread(client.block_ip, ip)
            finally:
                await asyncio.to_thread(client.disconnect)

            logger.info("Playbook1 — IP bloquée : %s | alert_id=%s", ip, alert_id)

            # Persistance en PostgreSQL (non bloquant)
            await save_playbook_execution(
                playbook_id=_PLAYBOOK_ID,
                execution_mode="AUTO",
                target_value=ip,
                result={"status": "success", "action": "block_ip", "ip": ip},
                parameters_used={
                    "blocked_ip": ip,
                    "firewall": "pfSense",
                    "host": str(config.PFSENSE_HOST or ""),
                    "action": "block_ip",
                },
                alert_id=alert_id,
            )

            return {"status": "success", "action": "block_ip", "ip": ip, "playbook": "1"}
        except Exception as exc:
            logger.error("Playbook1 — erreur blocage %s : %s", ip, exc)
            return {"status": "error", "erreur": str(exc)}
