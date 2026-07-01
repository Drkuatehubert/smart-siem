import asyncio
import logging
import os

from soar.notifiers.email_notifier import send_email
from soar.notifiers.webhook_notifier import send_webhook

logger = logging.getLogger("soar.alerting")


async def dispatch_notification(alert: dict):
    tasks = []
    if os.getenv("SMTP_HOST"):
        tasks.append(send_email(alert))
    if os.getenv("SLACK_WEBHOOK_URL"):
        tasks.append(send_webhook(alert))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
