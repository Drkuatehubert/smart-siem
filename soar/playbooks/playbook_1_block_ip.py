import asyncio
import logging

from soar.clients.pfsense_client import PfSenseClient
from soar.playbooks.base_playbook import BasePlaybook

logger = logging.getLogger(__name__)


class Playbook1BlockIP(BasePlaybook):
    async def execute(self, alert: dict) -> dict:
        ip = alert.get("source_ip") or alert.get("normalized_fields", {}).get("source_ip")
        if not ip:
            return {"status": "skipped", "reason": "no source_ip"}

        try:
            client = PfSenseClient()
            await asyncio.to_thread(client.connect)
            try:
                await asyncio.to_thread(client.block_ip, ip)
            finally:
                await asyncio.to_thread(client.disconnect)

            logger.info("Playbook1 — IP bloquée : %s | alert_id=%s", ip, alert.get("id"))
            return {"status": "success", "action": "block_ip", "ip": ip, "playbook": "1"}
        except Exception as exc:
            logger.error("Playbook1 — erreur blocage %s : %s", ip, exc)
            return {"status": "error", "erreur": str(exc)}
