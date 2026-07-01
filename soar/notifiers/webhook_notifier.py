import logging
import os

logger = logging.getLogger("soar.notifiers.webhook")

try:
    import httpx

    async def send_webhook(alert: dict):
        url = os.getenv("SLACK_WEBHOOK_URL", "")
        if not url:
            return
        payload = {
            "text": (
                f"*[SmartSIEM]* Alerte `{alert.get('severity')}` detectee\n"
                f"> Regle  : {alert.get('rule_id', 'inconnue')}\n"
                f"> ID     : {alert.get('id', '')}\n"
                f"> Detail : {alert.get('description', '')}"
            )
        }
        try:
            async with httpx.AsyncClient() as client:
                await client.post(url, json=payload, timeout=10)
        except Exception as exc:
            logger.error("Webhook erreur : %s", exc)

except ImportError:
    async def send_webhook(alert: dict):
        pass
