import logging
import os
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger("soar.notifiers.email")


async def send_email(alert: dict):
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASSWORD", "")
    sender = os.getenv("SMTP_FROM", "siem@example.com")
    recipients = [user]

    body = (
        f"Alerte SmartSIEM\n"
        f"Niveau : {alert.get('severity')}\n"
        f"Regle  : {alert.get('rule_id')}\n"
        f"ID     : {alert.get('id')}\n"
        f"Detail : {alert.get('description', '')}"
    )
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = f"[SIEM] Alerte {alert.get('severity')} detectee"
    msg["From"] = sender
    msg["To"] = ",".join(recipients)

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as s:
            s.starttls()
            s.login(user, password)
            s.sendmail(sender, recipients, msg.as_string())
    except Exception as exc:
        logger.error("Email erreur : %s", exc)
