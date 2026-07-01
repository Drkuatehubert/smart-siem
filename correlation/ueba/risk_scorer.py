"""
correlation/ueba/risk_scorer.py — Scoreur de risque UEBA dynamique avec decay

Responsable : Module UEBA — Analyse comportementale
Exigences   : RF-UEBA-04 (score de risque dynamique), RF-UEBA-05 (decay du score)
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict

from elasticsearch import AsyncElasticsearch

logger = logging.getLogger("correlation.ueba.risk_scorer")


def _level_from_score(score: int) -> str:
    """Convertit le score UEBA en niveau SIEM standardisé."""
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "WARNING"
    return "INFO"


async def compute_risk_score(es: AsyncElasticsearch, entity_id: str, anomaly_result: Dict[str, Any]) -> int:
    """
    Calcule le score de risque cumulatif d'une entité en intégrant un decay temporel.
    
    Algorithme :
      1. Récupère le dernier score de risque enregistré dans idx-alerts pour cette entité.
      2. Applique un decay exponentiel (5% de baisse par heure).
      3. Combine le score courant avec le score historique résiduel.
      4. Si le score combiné dépasse le seuil (>= 70), indexe une alerte de sécurité.
    """
    new_anomaly_score = int(anomaly_result.get("score", 0))
    now = datetime.now(timezone.utc)
    decayed_prev_score = 0.0

    # ──────────────────────────────────────────────────────────────────────
    # 1. Recherche du dernier score et calcul du decay
    # ──────────────────────────────────────────────────────────────────────
    try:
        # Recherche la dernière alerte UEBA pour cet utilisateur
        res = await es.search(
            index="idx-alerts",
            query={
                "bool": {
                    "must": [
                        {"term": {"username": entity_id}},
                        {"term": {"rule_id": "ueba-detection"}},
                    ]
                }
            },
            sort=[{"created_at": {"order": "desc"}}],
            size=1,
        )
        hits = res.get("hits", {}).get("hits", [])
        if hits:
            prev_alert = hits[0]["_source"]
            prev_score = float(prev_alert.get("score_risque", 0))
            created_at_str = prev_alert.get("created_at")
            if created_at_str:
                # Suppression du suffixe Z si présent pour fromisoformat
                if created_at_str.endswith("Z"):
                    created_at_str = created_at_str[:-1] + "+00:00"
                prev_time = datetime.fromisoformat(created_at_str)
                time_diff = now - prev_time
                hours_elapsed = time_diff.total_seconds() / 3600.0

                # Formule de decay exponentiel : 5% par heure
                decay_rate = 0.05
                decayed_prev_score = prev_score * math.exp(-decay_rate * hours_elapsed)
                logger.debug(
                    "Decay for %s: previous_score=%.1f hours_elapsed=%.2f decayed_score=%.1f",
                    entity_id, prev_score, hours_elapsed, decayed_prev_score
                )
    except Exception as exc:
        logger.warning("Could not compute risk decay for %s: %s", entity_id, exc)

    # ──────────────────────────────────────────────────────────────────────
    # 2. Combinaison des scores (nouveau + résiduel)
    # ──────────────────────────────────────────────────────────────────────
    # On ajoute la moitié du score résiduel au nouveau score d'anomalie, capé à 100
    combined_score = min(new_anomaly_score + int(decayed_prev_score * 0.5), 100)
    
    # Si le score historique résiduel est plus élevé que le score courant combiné, on garde le résiduel
    combined_score = max(combined_score, min(int(decayed_prev_score), 100))

    logger.info(
        "Risk score computed for %s: new_anomaly=%d decayed_prev=%.1f combined=%d",
        entity_id, new_anomaly_score, decayed_prev_score, combined_score
    )

    # ──────────────────────────────────────────────────────────────────────
    # 3. Création de l'alerte de sécurité si le score est significatif (>= 70)
    # ──────────────────────────────────────────────────────────────────────
    if combined_score >= 70:
        now_str = now.isoformat()
        level = _level_from_score(combined_score)
        
        alert_doc = {
            "niveau": level,
            "statut": "ouvert",
            "score_risque": combined_score,
            "commentaires": f"UEBA: {', '.join(anomaly_result.get('reasons', []))}",
            "created_at": now_str,
            "updated_at": now_str,
            "log_refs": [],
            "rule_id": "ueba-detection",
            "rule_nom": "Detection comportementale UEBA",
            "source_ip": anomaly_result.get("source_ip"),
            "host": anomaly_result.get("host"),
            "username": entity_id,
            "soar_recommended": combined_score >= 90,  # Recommandation automatique SOAR si critique
            "soar_approved": False,
            "ueba_context": {
                **anomaly_result,
                "decayed_previous_score": decayed_prev_score,
                "new_anomaly_score": new_anomaly_score,
            },
        }
        
        await es.index(index="idx-alerts", document=alert_doc)
        logger.warning(
            "🚨 UEBA Alert created for %s with score %d (Level: %s)",
            entity_id, combined_score, level
        )

    return combined_score
