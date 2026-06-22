"""playbooks/disable_account.py — Désactivation compte (RF-ALR-04)"""
import logging
from soar.playbooks.base_playbook import BasePlaybook
logger = logging.getLogger("soar.playbooks.disable_account")
class DisableAccountPlaybook(BasePlaybook):
    def __init__(self, es): self.es = es
    async def execute(self, alert: dict) -> dict:
        username = alert.get("normalized_fields",{}).get("username")
        if not username: return {"status":"skipped","reason":"Utilisateur introuvable"}
        res = await self.es.search(index="idx-users",body={"query":{"term":{"username":username}},"size":1})
        if not res["hits"]["hits"]: return {"status":"skipped","reason":f"Utilisateur {username} non trouvé dans SIEM"}
        user_id = res["hits"]["hits"][0]["_id"]
        await self.es.update(index="idx-users",id=user_id,body={"doc":{"is_active":False}})
        logger.info("Compte désactivé : %s", username)
        return {"status":"success","action":"disable_account","target":username}
