import asyncio
import json
import logging
import time

import redis

from soar import config
from soar.db import get_pg
from soar.orchestrator import handle_alert

logger = logging.getLogger("soar.worker")


def _connect() -> redis.Redis:
    """Crée une connexion Redis avec timeout socket explicite."""
    # socket_timeout=None : pas de timeout socket pendant blpop (timeout applicatif = 5s)
    # socket_connect_timeout=5 : échec rapide si Redis est injoignable au démarrage
    client = redis.from_url(
        config.CELERY_BROKER,
        decode_responses=True,
        socket_timeout=None,
        socket_connect_timeout=5,
    )
    client.ping()
    return client


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )
    logger.info("SOAR worker démarré — écoute sur la queue 'soar_alerts'")

    # Connexion PG eagerly pour seeder les playbooks système
    asyncio.run(get_pg())

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
                    result = asyncio.run(handle_alert(alert))
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
