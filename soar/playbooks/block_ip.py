"""playbooks/block_ip.py — Blocage IP (RF-ALR-04)"""
import subprocess, logging
from soar.playbooks.base_playbook import BasePlaybook
logger = logging.getLogger("soar.playbooks.block_ip")
class BlockIPPlaybook(BasePlaybook):
    async def execute(self, alert: dict) -> dict:
        ip = alert.get("source_ip") or alert.get("normalized_fields",{}).get("source_ip")
        if not ip: return {"status":"skipped","reason":"IP introuvable dans l alerte"}
        try:
            subprocess.run(["iptables","-A","INPUT","-s",ip,"-j","DROP"], check=True, timeout=10)
            logger.info("IP bloquée : %s", ip)
            return {"status":"success","action":"block_ip","target":ip}
        except Exception as e:
            logger.error("Erreur blocage IP %s: %s", ip, e)
            return {"status":"error","reason":str(e)}
