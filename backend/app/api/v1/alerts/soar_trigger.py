import json
import logging
from typing import Optional

from app.core.elasticsearch import get_es_client
from app.core.redis_client import get_redis_client

logger = logging.getLogger("soar.trigger")

_SOAR_SEVERITIES = {"HIGH", "CRITICAL"}
_ALERT_INDEX     = "alert-mirror"


async def trigger_soar(alert: dict) -> None:
    """Publie l'alerte dans la queue Redis soar_alerts si level HIGH ou CRITICAL.

    Appelé avec un dict d'alerte déjà chargé (champ 'level' depuis alert-mirror).
    """
    if alert.get("level") not in _SOAR_SEVERITIES:
        return
    try:
        r = get_redis_client()
        payload = json.dumps({
            "id":          alert.get("id"),
            "pg_alert_id": alert.get("pg_alert_id", ""),
            "severity":    alert.get("level", ""),
            "source_ip":   alert.get("source_ips", [""])[0] if alert.get("source_ips") else "",
            "title":       alert.get("title", ""),
            "rule_name":   alert.get("rule_name", ""),
        })
        await r.lpush("soar_alerts", payload)
        logger.info(
            "SOAR trigger : alert_id=%s severity=%s",
            alert.get("id"), alert.get("level"),
        )
    except Exception as exc:
        logger.error("SOAR trigger failed : %s", exc)


async def trigger_soar_by_id(alert_id: str) -> None:
    """Récupère l'alerte depuis alert-mirror par son pg_alert_id (UUID PostgreSQL)
    puis déclenche le SOAR si le niveau est HIGH ou CRITICAL.

    Appelé par l'endpoint /internal/alert-triggered que le moteur de corrélation
    contacte après chaque insertion d'alerte dans PostgreSQL.
    """
    try:
        es = get_es_client()
        res = await es.search(
            index=_ALERT_INDEX,
            body={
                "query": {"term": {"pg_alert_id": alert_id}},
                "size": 1,
            },
        )
        hits = res["hits"]["hits"]
        if not hits:
            logger.warning("SOAR trigger_by_id : alerte %s introuvable dans %s", alert_id, _ALERT_INDEX)
            return
        src = hits[0]["_source"]
        alert = {
            "id":          hits[0]["_id"],
            "pg_alert_id": alert_id,
            "level":       src.get("level", ""),
            "source_ips":  src.get("source_ips", []),
            "title":       src.get("title", ""),
            "rule_name":   src.get("rule_name", ""),
        }
        await trigger_soar(alert)
    except Exception as exc:
        logger.error("SOAR trigger_by_id failed (alert_id=%s) : %s", alert_id, exc)
