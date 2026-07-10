import asyncio
import logging
import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from soar.playbooks.base_playbook import BasePlaybook

logger = logging.getLogger(__name__)

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SOC_EMAIL = os.environ.get("SOC_EMAIL", "")


class Playbook3Escalate(BasePlaybook):
    async def execute(self, alert: dict) -> dict:
        alert_id  = alert.get("alert_id", alert.get("id", "unknown"))
        level     = alert.get("level", alert.get("severity", "HIGH"))
        title     = alert.get("title", "Alerte détectée")
        source_ips = alert.get("source_ips", [])
        if not source_ips and alert.get("source_ip"):
            source_ips = [alert["source_ip"]]
        rule_name = alert.get("rule_name", alert.get("rule_id", ""))
        timestamp = alert.get("timestamp", datetime.utcnow().isoformat())

        email_result = await asyncio.to_thread(
            self._send_email, alert_id, level, title, source_ips, rule_name, timestamp
        )

        logger.info(
            "Playbook3 — escalade : alert_id=%s level=%s email=%s",
            alert_id, level, email_result,
        )
        return {
            "status": "success",
            "action": "escalate",
            "playbook": "3",
            "email_sent": email_result,
            "alert_id": alert_id,
        }

    def _send_email(
        self,
        alert_id: str,
        level: str,
        title: str,
        source_ips: list,
        rule_name: str,
        timestamp: str,
    ) -> bool:
        if not SMTP_USER or not SMTP_PASSWORD or not SOC_EMAIL:
            logger.warning(
                "Email non configuré — SMTP_USER, SMTP_PASSWORD ou SOC_EMAIL manquant"
            )
            return False

        recipients = [e.strip() for e in SOC_EMAIL.split(",") if e.strip()]
        if not recipients:
            logger.warning("SOC_EMAIL ne contient aucune adresse valide")
            return False

        try:
            ips_str = ", ".join(source_ips) if source_ips else "N/A"

            msg = MIMEMultipart("alternative")
            msg["From"] = SMTP_USER
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = f"[SMART SIEM] {level} — {title[:60]}"

            body_text = f"""
SMART SIEM — ALERTE DE SECURITE
================================

Niveau     : {level}
Titre      : {title}
Regle      : {rule_name}
IP source  : {ips_str}
Horodatage : {timestamp}
Alert ID   : {alert_id}

ACTION REQUISE :
Connectez-vous sur http://192.168.100.1:5176
et traitez cette alerte immediatement.

--
Smart SIEM — UCAC-ICAM Promotion 2028
Module SOAR — Playbook Escalade automatique
"""

            body_html = f"""
<html><body>
<div style="font-family:Arial;max-width:600px;margin:auto;border:2px solid #E24B4A;border-radius:8px;overflow:hidden">
  <div style="background:#1e3a5f;padding:20px;color:white">
    <h2 style="margin:0">SMART SIEM — ALERTE {level}</h2>
    <p style="margin:4px 0;opacity:.8;font-size:14px">Systeme de detection automatique</p>
  </div>
  <div style="padding:20px">
    <table style="width:100%;border-collapse:collapse">
      <tr>
        <td style="padding:8px;font-weight:bold;color:#555;width:140px">Titre</td>
        <td style="padding:8px">{title}</td>
      </tr>
      <tr style="background:#f5f5f5">
        <td style="padding:8px;font-weight:bold;color:#555">Niveau</td>
        <td style="padding:8px">
          <span style="background:#E24B4A;color:white;padding:2px 8px;border-radius:4px;font-weight:bold">
            {level}
          </span>
        </td>
      </tr>
      <tr>
        <td style="padding:8px;font-weight:bold;color:#555">Règle MITRE</td>
        <td style="padding:8px">{rule_name}</td>
      </tr>
      <tr style="background:#f5f5f5">
        <td style="padding:8px;font-weight:bold;color:#555">IP source</td>
        <td style="padding:8px;font-family:monospace">{ips_str}</td>
      </tr>
      <tr>
        <td style="padding:8px;font-weight:bold;color:#555">Horodatage</td>
        <td style="padding:8px">{timestamp}</td>
      </tr>
      <tr style="background:#f5f5f5">
        <td style="padding:8px;font-weight:bold;color:#555">Alert ID</td>
        <td style="padding:8px;font-family:monospace;font-size:12px">{alert_id}</td>
      </tr>
    </table>
    <div style="margin-top:20px;text-align:center">
      <a href="http://192.168.100.1:5176"
         style="background:#1e3a5f;color:white;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:bold;display:inline-block">
        Traiter l'alerte dans le SIEM
      </a>
    </div>
  </div>
  <div style="background:#f5f5f5;padding:12px;text-align:center;font-size:12px;color:#888">
    Smart SIEM — UCAC-ICAM Promotion 2028 — Module SOAR
  </div>
</div>
</body></html>
"""

            msg.attach(MIMEText(body_text, "plain", "utf-8"))
            msg.attach(MIMEText(body_html, "html", "utf-8"))

            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, recipients, msg.as_string())

            logger.info("Email envoyé à %s (alert_id=%s)", recipients, alert_id)
            return True

        except Exception as exc:
            logger.error("Erreur envoi email : %s", exc)
            return False
