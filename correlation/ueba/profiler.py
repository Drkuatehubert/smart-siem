"""
correlation/ueba/profiler.py — Profilage UEBA enrichi

Responsable : Module UEBA — Analyse comportementale
Exigences   : RF-UEBA-01 (modélisation de profil), RF-UEBA-02 (IP, géo, agents)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from statistics import mean
from typing import Any, Dict

from elasticsearch import AsyncElasticsearch

logger = logging.getLogger("correlation.ueba.profiler")


async def compute_profile(es: AsyncElasticsearch, entity_id: str, entity_type: str = "user") -> Dict[str, Any]:
    """
    Calcule et persiste le profil comportemental d'une entité (utilisateur ou machine).
    Analyse l'historique sur les 7 derniers jours pour extraire les patterns habituels :
      * Horaires de connexion habituels (heures de la journée)
      * Volume moyen de logs par heure
      * Adresses IP sources connues
      * Machines (hosts) habituellement associées
      * Pays géographiques (geo_country) de connexion habituels
      * User Agents (navigateurs/clients) habituels
    """
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=7)).isoformat()
    username_field = "normalized_fields.username" if entity_type == "user" else "host"

    query = {
        "bool": {
            "must": [
                {"range": {"timestamp": {"gte": since}}},
                {"term": {username_field: entity_id}},
            ]
        }
    }

    res = await es.search(
        index="idx-logs",
        query=query,
        aggs={
            "hourly": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h"}},
            "source_ips": {"terms": {"field": "source_ip", "size": 50}},
            "hosts": {"terms": {"field": "host", "size": 50}},
            "countries": {"terms": {"field": "normalized_fields.geo_country.keyword", "size": 50, "missing": "Unknown"}},
            "user_agents": {"terms": {"field": "normalized_fields.user_agent.keyword", "size": 50, "missing": "Unknown"}},
        },
        size=0,
    )

    buckets = res.get("aggregations", {}).get("hourly", {}).get("buckets", [])
    # Extrait les heures d'activité (format HH)
    active_hours = []
    for b in buckets:
        if b["doc_count"] > 0:
            key_str = b.get("key_as_string")
            if key_str and "T" in key_str:
                active_hours.append(key_str.split("T")[1][:2])

    volumes = [b["doc_count"] for b in buckets]
    avg_volume = mean(volumes) if volumes else 0.0

    profile = {
        "entity_id": entity_id,
        "entity_type": entity_type,
        "typical_hours": sorted(set(active_hours)),
        "avg_volume_per_hour": float(avg_volume),
        "known_source_ips": [b["key"] for b in res.get("aggregations", {}).get("source_ips", {}).get("buckets", [])],
        "known_hosts": [b["key"] for b in res.get("aggregations", {}).get("hosts", {}).get("buckets", [])],
        "known_countries": [b["key"] for b in res.get("aggregations", {}).get("countries", {}).get("buckets", [])],
        "known_user_agents": [b["key"] for b in res.get("aggregations", {}).get("user_agents", {}).get("buckets", [])],
        "updated_at": now.isoformat(),
    }

    await es.index(index="idx-ueba-profiles", id=entity_id, document=profile)
    logger.info(
        "Computed behavior profile for %s %s: %d IPs, %d countries, %d agents",
        entity_type, entity_id, len(profile["known_source_ips"]),
        len(profile["known_countries"]), len(profile["known_user_agents"])
    )
    return profile
