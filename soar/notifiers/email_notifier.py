"""notifiers/email_notifier.py — Notification SMTP"""
import smtplib, os
from email.mime.text import MIMEText

async def send_email(alert: dict):
    smtp_host = os.getenv("SMTP_HOST",""); smtp_port = int(os.getenv("SMTP_PORT",587))
    user = os.getenv("SMTP_USER",""); password = os.getenv("SMTP_PASSWORD","")
    sender = os.getenv("SMTP_FROM","siem@example.com"); recipients = [user]
    msg = MIMEText(f"Alerte SmartSIEM\nNiveau: {alert.get('niveau')}\nStatut: {alert.get('statut')}\nID: {alert.get('id')}")
    msg["Subject"] = f"[SIEM] Alerte {alert.get('niveau')} détectée"; msg["From"] = sender; msg["To"] = ",".join(recipients)
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as s:
            s.starttls(); s.login(user, password); s.sendmail(sender, recipients, msg.as_string())
    except Exception as e:
        import logging; logging.getLogger("soar").error("Email erreur: %s", e)
