"""
evaluators/sequential.py — Évaluateur de règles séquentielles (RF-COR-02)

Évalue une règle de type `sequentielle` : vérifie que chaque étape
(steps = liste de {field, value}) trouve au moins un log dans la fenêtre
temporelle.

Améliorations :
  * import absolu ;
  * validation explicite que `steps` n'est pas vide ;
  * retourne les IDs de chaque étape (utile pour l'alerte) ;
  * logging explicite des matches partiels.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from elasticsearch import AsyncElasticsearch

logger = logging.getLogger("correlation.evaluators.sequential")


class SequentialEvaluator:
    """Règle de type `sequentielle` — vérifie une séquence d'événements."""

    def __init__(self, es: AsyncElasticsearch) -> None:
        self.es = es

    async def evaluate(self, rule: Dict[str, Any]) -> Tuple[bool, List[str]]:
        cond: Dict[str, Any] = rule.get("condition", {})
        steps: List[Dict[str, Any]] = cond.get("steps") or []
        if not steps:
            logger.warning("Règle séquentielle sans steps : %s", rule.get("id"))
            return False, []

        window = int(rule.get("fenetre_temporelle_s", 300))
        since = (datetime.now(timezone.utc) - timedelta(seconds=window)).isoformat()

        matched_ids: List[str] = []
        for step in steps:
            field = step.get("field")
            value = step.get("value")
            if not field or value is None:
                logger.warning("Step mal formé dans la règle %s : %s", rule.get("id"), step)
                return False, []
            res = await self.es.search(
                index="idx-logs",
                query={"bool": {"must": [
                    {"range": {"timestamp": {"gte": since}}},
                    {"term": {field: value}},
                ]}},
                size=1,
            )
            hits = res["hits"]["hits"]
            if not hits:
                logger.debug(
                    "Sequential miss: rule=%s step field=%s value=%s",
                    rule.get("id"), field, value,
                )
                return False, []
            matched_ids.append(hits[0]["_id"])

        logger.info(
            "Sequential match: rule=%s steps=%d window=%ds",
            rule.get("id"), len(steps), window,
        )
        return True, matched_ids