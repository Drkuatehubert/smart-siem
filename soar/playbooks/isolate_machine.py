"""playbooks/isolate_machine.py — Isolation machine (RF-ALR-04)"""
import logging
from soar.playbooks.base_playbook import BasePlaybook
logger = logging.getLogger("soar.playbooks.isolate_machine")
class IsolateMachinePlaybook(BasePlaybook):
    async def execute(self, alert: dict) -> dict:
        host = alert.get("host","")
        if not host: return {"status":"skipped","reason":"Host introuvable"}
        logger.warning("ISOLATION REQUISE pour %s — action manuelle nécessaire en environnement réel", host)
        return {"status":"simulated","action":"isolate_machine","target":host,"note":"Isolation réseau à déclencher manuellement ou via API pare-feu"}
