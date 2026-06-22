"""notifiers/webhook_notifier.py — Notification Slack/Teams webhook"""
import os, json
try:
    import httpx
    async def send_webhook(alert: dict):
        url = os.getenv("SLACK_WEBHOOK_URL","")
        if not url: return
        payload = {"text":f"*[SmartSIEM]* Alerte `{alert.get('niveau')}` détectée\n> Règle : {alert.get('rule_id','inconnue')}\n> Statut : {alert.get('statut')}"}
        async with httpx.AsyncClient() as c:
            await c.post(url, json=payload, timeout=10)
except ImportError:
    async def send_webhook(alert: dict): pass
