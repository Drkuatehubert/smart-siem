import logging

from soar.alerting import dispatch_notification
from soar.playbooks.base_playbook import BasePlaybook

logger = logging.getLogger(__name__)


class Playbook3Escalate(BasePlaybook):
    async def execute(self, alert: dict) -> dict:
        await dispatch_notification(alert)
        logger.info(
            "Playbook3 — escalade : severity=%s rule_id=%s alert_id=%s",
            alert.get("severity"), alert.get("rule_id"), alert.get("id"),
        )
        return {"status": "success", "action": "escalate", "playbook": "3"}
