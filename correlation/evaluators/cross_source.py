"""Evaluateur de correlation inter-sources.

Une regle `cross_source` exige plusieurs evenements provenant de sources
differententes mais rattaches a la meme entite : utilisateur, IP ou host.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from elasticsearch import AsyncElasticsearch

logger = logging.getLogger("correlation.evaluators.cross_source")


class CrossSourceEvaluator:
    """Detecte une attaque quand plusieurs sources confirment le meme signal."""

    _MAX_SIZE = 500

    def __init__(self, es: AsyncElasticsearch) -> None:
        self.es = es

    async def evaluate(self, rule: Dict[str, Any]) -> Tuple[bool, List[str]]:
        cond: Dict[str, Any] = rule.get("condition", {})
        steps: List[Dict[str, Any]] = cond.get("steps") or []
        entity_field = cond.get("entity_field", "normalized_fields.username")
        min_sources = int(cond.get("min_sources", max(len(steps), 2)))
        window = int(rule.get("fenetre_temporelle_s", 300))
        since = (datetime.now(timezone.utc) - timedelta(seconds=window)).isoformat()

        if not steps:
            logger.warning("Regle cross_source sans steps: %s", rule.get("id"))
            return False, []

        should: List[Dict[str, Any]] = []
        for step in steps:
            field = step.get("field")
            value = step.get("value")
            if not field or value is None:
                logger.warning("Step cross_source mal forme dans %s: %s", rule.get("id"), step)
                return False, []
            should.append({"term": {field: value}})

        res = await self.es.search(
            index="idx-logs",
            query={
                "bool": {
                    "must": [{"range": {"timestamp": {"gte": since}}}],
                    "should": should,
                    "minimum_should_match": 1,
                }
            },
            size=self._MAX_SIZE,
        )

        by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for hit in res["hits"]["hits"]:
            source = hit.get("_source", {})
            entity = self._extract(source, entity_field)
            if entity:
                by_entity[str(entity)].append(hit)

        for entity, hits in by_entity.items():
            source_names = {
                self._extract(h.get("_source", {}), "source_id")
                or self._extract(h.get("_source", {}), "log_type")
                or self._extract(h.get("_source", {}), "host")
                for h in hits
            }
            source_names.discard(None)
            if len(source_names) >= min_sources:
                logger.info(
                    "Cross-source match: rule=%s entity=%s sources=%d",
                    rule.get("id"), entity, len(source_names),
                )
                return True, [h["_id"] for h in hits[:min_sources]]

        return False, []

    def _extract(self, source: Dict[str, Any], dotted_field: str) -> Any:
        """Lit un champ potentiellement imbrique avec la notation point."""
        current: Any = source
        for part in dotted_field.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current
