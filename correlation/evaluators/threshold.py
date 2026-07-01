"""
evaluators/threshold.py â€” Ã‰valuateur de rÃ¨gles Ã  seuil (RF-COR-01)

Ã‰value une rÃ¨gle de type `seuil` : on compte dans une fenÃªtre temporelle
le nombre de logs dont un champ donnÃ© matche une valeur, et on dÃ©clenche
si on dÃ©passe le seuil.

AmÃ©liorations :
  * import absolu ;
  * cap de la `size` (max 200) ;
  * logging explicite des matches ;
  * ne retourne jamais plus de `threshold` IDs (Ã©vite des tableaux dÃ©mesurÃ©s).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from elasticsearch import AsyncElasticsearch

logger = logging.getLogger("correlation.evaluators.threshold")

ù
class ThresholdEvaluator:
    """RÃ¨gle de type `seuil` â€” compte les logs dans une fenÃªtre temporelle."""

    _MAX_SIZE = 200

    def __init__(self, es: AsyncElasticsearch) -> None:
        self.es = es

    async def evaluate(self, rule: Dict[str, Any]) -> Tuple[bool, List[str]]:
        cond: Dict[str, Any] = rule.get("condition", {})
        window = int(rule.get("fenetre_temporelle_s", 60))
        threshold = int(cond.get("threshold", 5))
        since = (datetime.now(timezone.utc) - timedelta(seconds=window)).isoformat()

        must: List[Dict[str, Any]] = [{"range": {"timestamp": {"gte": since}}}]
        field = cond.get("field")
        value = cond.get("value")
        if field and value is not None:
            must.append({"term": {field: value}})

        size = min(threshold + 10, self._MAX_SIZE)
        res = await self.es.search(
            index="idx-logs",
            query={"bool": {"must": must}},
            size=size,
        )
        count = res["hits"]["total"]["value"]
        if count >= threshold:
            log_ids = [h["_id"] for h in res["hits"]["hits"][:threshold]]
            logger.info(
                "Threshold match: rule=%s count=%d threshold=%d window=%ds",
                rule.get("id"), count, threshold, window,
            )
            return True, log_ids
        return False, []
