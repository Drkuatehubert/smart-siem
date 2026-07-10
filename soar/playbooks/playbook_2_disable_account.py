import asyncio
import logging

from soar import config
from soar.alerting import dispatch_notification
from soar.clients.ad_client import ADClient
from soar.db import save_playbook_execution
from soar.playbooks.base_playbook import BasePlaybook

logger = logging.getLogger(__name__)

_PLAYBOOK_ID = "00000001-0000-0002-0000-000000000001"


class Playbook2DisableAccount(BasePlaybook):
    async def execute(self, alert: dict) -> dict:
        username = alert.get("username") or alert.get("normalized_fields", {}).get("username")
        if not username:
            return {"status": "skipped", "reason": "no username"}

        alert_id = alert.get("alert_id") or alert.get("pg_alert_id") or alert.get("id", "unknown")

        await dispatch_notification(alert)
        logger.info(
            "Playbook2 — notification envoyée, attente %ds avant désactivation de '%s' | alert_id=%s",
            config.CONFIRM_DELAY_SECONDS, username, alert_id,
        )

        await asyncio.sleep(config.CONFIRM_DELAY_SECONDS)

        if alert_id in config.CANCELLED_ALERTS:
            config.CANCELLED_ALERTS.discard(alert_id)
            logger.info("Playbook2 — annulé pour alert_id=%s", alert_id)
            return {"status": "cancelled"}

        try:
            client = ADClient()
            await asyncio.to_thread(client.connect)
            try:
                await asyncio.to_thread(client.disable_account, username)
            finally:
                await asyncio.to_thread(client.disconnect)

            logger.info(
                "Playbook2 — compte désactivé : '%s' | alert_id=%s", username, alert_id
            )

            # Persistance en PostgreSQL (non bloquant)
            await save_playbook_execution(
                playbook_id=_PLAYBOOK_ID,
                execution_mode="CONFIRM",
                target_value=username,
                result={"status": "success", "action": "disable_account", "username": username},
                parameters_used={
                    "username": username,
                    "domain": str(config.AD_HOST or "ctu.local"),
                    "action": "disable_account",
                },
                alert_id=alert_id if alert_id != "unknown" else None,
            )

            return {
                "status": "success",
                "action": "disable_account",
                "username": username,
                "playbook": "2",
            }
        except Exception as exc:
            logger.error("Playbook2 — erreur désactivation '%s' : %s", username, exc)
            await save_playbook_execution(
                playbook_id=_PLAYBOOK_ID,
                execution_mode="CONFIRM",
                target_value=username,
                result={"status": "error", "action": "disable_account", "username": username, "erreur": str(exc)},
                parameters_used={"username": username, "action": "disable_account"},
                alert_id=alert_id if alert_id != "unknown" else None,
                status="failed",
            )
            return {"status": "error", "erreur": str(exc)}
