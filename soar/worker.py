import asyncio
import json
import logging
import time

import redis

from soar import config
from soar.orchestrator import handle_alert

logger = logging.getLogger("soar.worker")


def _connect(broker_url: str) -> redis.Redis:
    client = redis.from_url(broker_url, decode_responses=True)
    client.ping()
    return client


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )
    logger.info("SOAR worker démarré — écoute sur la queue 'soar_alerts'")

    while True:
        try:
            client = _connect(config.CELERY_BROKER)
            logger.info("Connecté à Redis : %s", config.CELERY_BROKER)

            while True:
                # BLPOP bloque jusqu'à 5s, retourne (key, value) ou None si timeout
                item = client.blpop("soar_alerts", timeout=5)
                if item is None:
                    continue

                _, raw = item

                try:
                    alert = json.loads(raw)
                except json.JSONDecodeError as exc:
                    logger.error("Message ignoré (JSON invalide) : %s — %s", raw[:200], exc)
                    continue

                alert_id = alert.get("id", "unknown")
                logger.info(
                    "Alerte reçue : id=%s rule=%s severity=%s",
                    alert_id, alert.get("rule_id"), alert.get("severity"),
                )

                try:
                    result = asyncio.run(handle_alert(alert))
                    logger.info("Alerte traitée : id=%s résultat=%s", alert_id, result)
                except Exception as exc:
                    logger.error("Erreur traitement alerte %s : %s", alert_id, exc)

        except redis.RedisError as exc:
            logger.error("Erreur Redis : %s — reconnexion dans 5s", exc)
            time.sleep(5)
        except Exception as exc:
            logger.error("Erreur inattendue : %s — reprise dans 5s", exc)
            time.sleep(5)


if __name__ == "__main__":
    main()
