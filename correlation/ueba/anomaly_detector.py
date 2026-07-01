"""
correlation/ueba/anomaly_detector.py — Détecteur d'anomalies UEBA enrichi

Responsable : Module UEBA — Analyse comportementale
Exigences   : RF-UEBA-02 (détection anomalies), RF-UEBA-03 (heure, volume, localisation, agent)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from elasticsearch import AsyncElasticsearch

logger = logging.getLogger("correlation.ueba.anomaly_detector")


async def detect_anomaly(
    es: AsyncElasticsearch,
    entity_id: str,
    current_hour: str,
    current_volume: int,
    *,
    source_ip: str | None = None,
    host: str | None = None,
    geo_country: str | None = None,
    user_agent: str | None = None,
) -> Dict[str, Any]:
    """
    Compare l'activité courante d'une entité avec son profil comportemental de référence.
    
    Pondération des scores d'anomalie :
      * Connexion hors horaires : +30
      * Volume inhabituel (> 3x la moyenne) : +30
      * Adresse IP inconnue : +20
      * Machine (host) inconnue : +20
      * Localisation géographique (pays) inconnue : +25
      * User Agent inconnu : +15
      
    Le score composite final est capé à 100.
    """
    try:
        profile = (await es.get(index="idx-ueba-profiles", id=entity_id))["_source"]
    except Exception:
        # Aucun profil n'existe encore pour cette entité
        logger.debug("No profile found for entity %s, anomaly score cannot be computed", entity_id)
        return {
            "entity_id": entity_id,
            "score": 0,
            "reasons": [],
            "evaluated_at": datetime.now(timezone.utc).isoformat()
        }

    reasons: list[str] = []
    score = 0

    # 1. Heure de connexion
    if current_hour not in profile.get("typical_hours", []):
        reasons.append(f"Connexion hors horaires habituels ({current_hour}h)")
        score += 30

    # 2. Volume d'activité
    avg = float(profile.get("avg_volume_per_hour") or 0)
    if avg > 0 and current_volume > avg * 3:
        reasons.append(f"Volume anormal: {current_volume} messages vs moyenne {avg:.1f}")
        score += 30

    # 3. Adresse IP source
    if source_ip and source_ip not in profile.get("known_source_ips", []):
        reasons.append(f"IP source inconnue pour l'entite: {source_ip}")
        score += 20

    # 4. Host (machine) destination/intermédiaire
    if host and host not in profile.get("known_hosts", []):
        reasons.append(f"Host inhabituel pour l'entite: {host}")
        score += 20

    # 5. Localisation géographique (Pays)
    known_countries = profile.get("known_countries", [])
    if geo_country and geo_country != "Unknown" and geo_country not in known_countries:
        reasons.append(f"Pays de connexion inhabituel: {geo_country}")
        score += 25

    # 6. User Agent (navigateur/client)
    known_agents = profile.get("known_user_agents", [])
    if user_agent and user_agent != "Unknown" and user_agent not in known_agents:
        reasons.append(f"User Agent / Client inhabituel: {user_agent}")
        score += 15

    result = {
        "entity_id": entity_id,
        "score": min(score, 100),
        "reasons": reasons,
        "source_ip": source_ip,
        "host": host,
        "geo_country": geo_country,
        "user_agent": user_agent,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }

    # Indexation de l'événement d'anomalie
    await es.index(index="idx-ueba-events", document=result)
    
    if score > 0:
        logger.info(
            "Anomaly detected for entity %s: score=%d reasons=%s",
            entity_id, result["score"], reasons
        )
    return result
