"""
correlation/evaluators/statistical.py — Évaluateur statistique pour règles de corrélation

Responsable : Module Corrélation & Détection
Exigences   : RF-COR-03 (détection statistique / z-score / baseline dynamique)

Ce module permet de détecter les anomalies de volume ou d'utilisation de ressources
en comparant l'activité courante à une baseline dynamique calculée sur une période
historique (par exemple les 7 derniers jours). Il utilise la formule du Z-Score :
    Z = (Valeur_Courante - Moyenne_Historique) / Écart_Type_Historique
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Tuple

from elasticsearch import AsyncElasticsearch

logger = logging.getLogger("correlation.evaluators.statistical")


class StatisticalEvaluator:
    """Évalue les règles de corrélation basées sur des anomalies statistiques (Z-score)."""

    def __init__(self, es: AsyncElasticsearch) -> None:
        self.es = es

    async def evaluate(self, rule: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Évalue une règle statistique.
        
        Structure attendue de la règle :
        {
            "id": "anomaly_data_exfil",
            "type": "statistical",
            "condition": {
                "field": "normalized_fields.bytes_sent",  # Optionnel (si vide, compte le volume de logs)
                "z_score_threshold": 3.0,                  # Seuil de Z-score (par défaut 3.0)
                "min_events": 10,                          # Nombre minimal d'événements requis pour valider la stat
                "baseline_window_s": 604800,               # Période de baseline en secondes (7 jours par défaut)
                "bucket_interval_s": 3600                  # Intervalle de découpage historique (1h par défaut)
            },
            "fenetre_temporelle_s": 300,                  # Fenêtre courante à évaluer (5 min par défaut)
            "niveau_alerte_genere": "HIGH"
        }
        """
        cond: Dict[str, Any] = rule.get("condition", {})
        field = cond.get("field")
        z_threshold = float(cond.get("z_score_threshold", 3.0))
        min_events = int(cond.get("min_events", 10))
        baseline_window = int(cond.get("baseline_window_s", 604800))
        bucket_interval = int(cond.get("bucket_interval_s", 3600))
        eval_window = int(rule.get("fenetre_temporelle_s", 300))

        now = datetime.now(timezone.utc)
        baseline_start = (now - timedelta(seconds=baseline_window)).isoformat()
        eval_start = (now - timedelta(seconds=eval_window)).isoformat()

        # ──────────────────────────────────────────────────────────────────────
        # 1. Récupération des données courantes (fenêtre d'évaluation)
        # ──────────────────────────────────────────────────────────────────────
        current_query: Dict[str, Any] = {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": eval_start}}}
                ]
            }
        }
        
        if field:
            current_query["bool"]["must"].append({"exists": {"field": field}})

        current_res = await self.es.search(
            index="idx-logs",
            query=current_query,
            size=100,
        )

        current_hits = current_res["hits"]["hits"]
        current_count = current_res["hits"]["total"]["value"]

        if current_count < min_events:
            logger.debug(
                "Rule %s: Evenements courants insuffisants (%d < %d)",
                rule.get("id"), current_count, min_events
            )
            return False, []

        if field:
            current_value = 0.0
            for hit in current_hits:
                source = hit.get("_source", {})
                val = self._extract(source, field)
                if isinstance(val, (int, float)):
                    current_value += float(val)
        else:
            current_value = float(current_count)

        # ──────────────────────────────────────────────────────────────────────
        # 2. Récupération de la baseline historique (agrégation temporelle)
        # ──────────────────────────────────────────────────────────────────────
        baseline_query: Dict[str, Any] = {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": baseline_start, "lt": eval_start}}}
                ]
            }
        }
        if field:
            baseline_query["bool"]["must"].append({"exists": {"field": field}})

        interval_str = f"{bucket_interval}s"

        aggs: Dict[str, Any] = {
            "history_buckets": {
                "date_histogram": {
                    "field": "timestamp",
                    "fixed_interval": interval_str
                }
            }
        }
        
        if field:
            aggs["history_buckets"]["aggs"] = {
                "metric_sum": {"sum": {"field": field}}
            }

        hist_res = await self.es.search(
            index="idx-logs",
            query=baseline_query,
            aggs=aggs,
            size=0,
        )

        buckets = hist_res.get("aggregations", {}).get("history_buckets", {}).get("buckets", [])
        if not buckets:
            logger.warning("Rule %s: Baseline vide ou inexistante", rule.get("id"))
            return False, []

        values: List[float] = []
        for bucket in buckets:
            if field:
                val = bucket.get("metric_sum", {}).get("value", 0.0)
                values.append(float(val or 0.0))
            else:
                values.append(float(bucket.get("doc_count", 0)))

        if len(values) < 3:
            logger.warning("Rule %s: Historique insuffisant pour calculer la baseline (%d buckets)", rule.get("id"), len(values))
            return False, []

        # ──────────────────────────────────────────────────────────────────────
        # 3. Calculs Statistiques (Moyenne & Écart-Type)
        # ──────────────────────────────────────────────────────────────────────
        n = len(values)
        mean_val = sum(values) / n
        variance = sum((x - mean_val) ** 2 for x in values) / n
        stddev = math.sqrt(variance)

        # ──────────────────────────────────────────────────────────────────────
        # 4. Évaluation du Z-score
        # ──────────────────────────────────────────────────────────────────────
        if stddev == 0:
            if current_value > mean_val:
                z_score = 999.0
            else:
                z_score = 0.0
        else:
            z_score = (current_value - mean_val) / stddev

        logger.info(
            "Rule %s stats: current_val=%.2f baseline_mean=%.2f stddev=%.2f z_score=%.2f (threshold=%.2f)",
            rule.get("id"), current_value, mean_val, stddev, z_score, z_threshold
        )

        if z_score >= z_threshold:
            matched_ids = [hit["_id"] for hit in current_hits]
            logger.warning(
                "Statistical Match detected for rule %s: z_score=%.2f >= %.2f (current_val=%.2f vs baseline_mean=%.2f)",
                rule.get("id"), z_score, z_threshold, current_value, mean_val
            )
            return True, matched_ids

        return False, []

    def _extract(self, source: Dict[str, Any], dotted_field: str) -> Any:
        """Lit un champ imbriqué avec la notation pointée."""
        current: Any = source
        for part in dotted_field.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current
