import asyncio
import json
import logging
import time

import redis

from soar import config
from soar.db import get_pg, save_playbook_execution
from soar.orchestrator import handle_alert

logger = logging.getLogger("soar.worker")

_PB_ESCALATE_UUID = "00000001-0000-0003-0000-000000000001"


def _connect() -> redis.Redis:
    """Crée une connexion Redis avec timeout socket explicite."""
    client = redis.from_url(
        config.CELERY_BROKER,
        decode_responses=True,
        socket_timeout=None,
        socket_connect_timeout=5,
    )
    client.ping()
    return client


async def _process_and_persist(alert: dict) -> dict:
    """Exécute handle_alert et persiste chaque résultat dans playbook_executions."""
    result = await handle_alert(alert)
    alert_id = alert.get("alert_id") or alert.get("id")

    for pb_result in result.get("playbooks_executed", []):
        action = pb_result.get("action", "")
        status = pb_result.get("status", "unknown")

        if action == "escalate":
            await save_playbook_execution(
                playbook_id=_PB_ESCALATE_UUID,
                execution_mode="AUTO",
                target_value=alert_id or "unknown",
                result=pb_result,
                parameters_used={
                    "severity": alert.get("level", alert.get("severity", "")),
                    "rule": alert.get("rule_name", ""),
                    "source": "auto",
                },
                alert_id=alert_id,
                status=status if status in ("success", "failed", "skipped") else "success",
            )
        elif action in ("", "block_ip") and status in ("skipped", "error"):
            # Enregistre les blocages échoués / ignorés que playbook_1 ne sauvegarde pas
            from soar.db import _BLOCK_IP_UUID
            await save_playbook_execution(
                playbook_id=_BLOCK_IP_UUID,
                execution_mode="AUTO",
                target_value=pb_result.get("ip") or pb_result.get("reason", "?"),
                result=pb_result,
                parameters_used={"reason": pb_result.get("reason", pb_result.get("erreur", ""))},
                alert_id=alert_id,
                status="failed" if status == "error" else "cancelled",
            )

    return result


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )
    logger.info("SOAR worker démarré — écoute sur la queue 'soar_alerts'")

    # Boucle asyncio UNIQUE et persistante pour tout le processus.
    # asyncio.run() crée et FERME la boucle à chaque appel, ce qui rend
    # le pool asyncpg inutilisable lors des appels suivants ("Event loop is closed").
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    loop.run_until_complete(get_pg())

    while True:
        try:
            client = _connect()
            logger.info("Connecté à Redis : %s", config.CELERY_BROKER)

            while True:
                item = client.blpop("soar_alerts", timeout=5)
                if item is None:
                    continue

                _, raw = item

                try:
                    alert = json.loads(raw)
                except json.JSONDecodeError as exc:
                    logger.error("Message ignoré (JSON invalide) : %s — %s", raw[:200], exc)
                    continue

                alert_id = alert.get("alert_id", alert.get("id", "?"))
                logger.info(
                    "[SOAR] Alerte reçue : %s  rule=%s  level=%s",
                    str(alert_id)[:8], alert.get("rule_name"), alert.get("level"),
                )

                try:
                    result = loop.run_until_complete(_process_and_persist(alert))
                    logger.info("[SOAR] Alerte traitée : %s  résultat=%s", str(alert_id)[:8], result)
                except Exception as exc:
                    logger.error("[SOAR] Erreur playbook %s : %s", str(alert_id)[:8], exc)

        except (redis.ConnectionError, redis.TimeoutError) as exc:
            logger.warning("Erreur Redis : %s — reconnexion dans 5s", exc)
            time.sleep(5)
        except Exception as exc:
            logger.error("Erreur inattendue : %s — reprise dans 5s", exc)
            time.sleep(5)


if __name__ == "__main__":
    main()
