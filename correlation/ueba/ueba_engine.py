"""
correlation/ueba/ueba_engine.py — Orchestrateur principal UEBA

Responsable : Module UEBA & SOAR
Exigences   : RF-UEBA-05 (déclenchement automatique SOAR), NFR-SEC-03 (audit)

Ce module s'exécute en continu (boucle asynchrone) :
  1. Identifie les entités actives (utilisateurs, IPs, machines) sur la dernière heure.
  2. Génère ou met à jour leur profil comportemental de référence (profiler.py).
  3. Détecte les anomalies de la dernière période (anomaly_detector.py).
  4. Calcule le score de risque consolidé avec decay temporel (risk_scorer.py).
  5. Déclenche automatiquement les playbooks SOAR pour les entités critiques (score >= 90).
"""

from __future__ import annotations

import asyncio
import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List

# Injection du dossier backend dans le path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "backend"))

from elasticsearch import AsyncElasticsearch

from app.config import settings
from correlation.ueba.profiler import compute_profile
from correlation.ueba.anomaly_detector import detect_anomaly
from correlation.ueba.risk_scorer import compute_risk_score
from soar.executor import execute_playbook

logger = logging.getLogger("correlation.ueba.engine")
logging.basicConfig(level=logging.INFO)


class UEBAEngine:
    """Orchestrateur comportemental du Smart SIEM."""

    def __init__(self, es: AsyncElasticsearch) -> None:
        self.es = es

    async def run_cycle(self, window_seconds: int = 3600) -> None:
        """
        Exécute un cycle complet d'analyse comportementale sur les logs récents.
        
        Paramètres
        ----------
        window_seconds : Fenêtre d'analyse courante (par défaut la dernière heure).
        """
        now = datetime.now(timezone.utc)
        since = (now - timedelta(seconds=window_seconds)).isoformat()
        current_hour_str = f"{now.hour:02d}"

        logger.info("Starting UEBA cycle for events since %s", since)

        # ──────────────────────────────────────────────────────────────────────
        # 1. Extraction des entités actives et de leurs métriques courantes
        # ──────────────────────────────────────────────────────────────────────
        try:
            res = await self.es.search(
                index="idx-logs",
                query={
                    "bool": {
                        "must": [
                            {"range": {"timestamp": {"gte": since}}}
                        ]
                    }
                },
                aggs={
                    "active_users": {
                        "terms": {"field": "normalized_fields.username.keyword", "size": 100},
                        "aggs": {
                            "source_ips": {"terms": {"field": "source_ip", "size": 5}},
                            "hosts": {"terms": {"field": "host", "size": 5}},
                            "countries": {"terms": {"field": "normalized_fields.geo_country.keyword", "size": 5}},
                            "user_agents": {"terms": {"field": "normalized_fields.user_agent.keyword", "size": 5}},
                        }
                    }
                },
                size=0,
            )
        except Exception as exc:
            logger.error("Failed to query active entities from Elasticsearch: %s", exc)
            return

        buckets = res.get("aggregations", {}).get("active_users", {}).get("buckets", [])
        logger.info("Found %d active users to analyze", len(buckets))

        for bucket in buckets:
            username = bucket["key"]
            volume = bucket["doc_count"]

            # Extraire les contextes les plus fréquents de l'activité courante
            ips = bucket.get("source_ips", {}).get("buckets", [])
            hosts = bucket.get("hosts", {}).get("buckets", [])
            countries = bucket.get("countries", {}).get("buckets", [])
            agents = bucket.get("user_agents", {}).get("buckets", [])

            ip = ips[0]["key"] if ips else None
            host = hosts[0]["key"] if hosts else None
            country = countries[0]["key"] if countries else "Unknown"
            user_agent = agents[0]["key"] if agents else "Unknown"

            try:
                # ──────────────────────────────────────────────────────────────
                # 2. Modélisation / Mise à jour du profil de l'entité
                # ──────────────────────────────────────────────────────────────
                # On vérifie si un profil existe déjà
                profile_exists = await self.es.exists(index="idx-ueba-profiles", id=username)
                if not profile_exists:
                    logger.info("No behavior profile found for user '%s'. Computing baseline...", username)
                    await compute_profile(self.es, username, entity_type="user")
                
                # ──────────────────────────────────────────────────────────────
                # 3. Détection d'anomalies
                # ──────────────────────────────────────────────────────────────
                anomaly_res = await detect_anomaly(
                    self.es,
                    entity_id=username,
                    current_hour=current_hour_str,
                    current_volume=volume,
                    source_ip=ip,
                    host=host,
                    geo_country=country,
                    user_agent=user_agent
                )

                # ──────────────────────────────────────────────────────────────
                # 4. Calcul du score de risque dynamique (avec decay)
                # ──────────────────────────────────────────────────────────────
                risk_score = await compute_risk_score(self.es, username, anomaly_res)

                # ──────────────────────────────────────────────────────────────
                # 5. Déclenchement automatique SOAR (si score >= 90)
                # ──────────────────────────────────────────────────────────────
                if risk_score >= 90:
                    logger.warning(
                        "🔥 CRITICAL UEBA RISK detected for user '%s' (score=%d). Triggering SOAR playbook...",
                        username, risk_score
                    )
                    
                    # Simulation d'alerte structurée pour le SOAR
                    alert_payload = {
                        "id": f"ueba-auto-{username}-{int(now.timestamp())}",
                        "rule_id": "ueba-detection",
                        "rule_nom": "Detection comportementale UEBA",
                        "niveau": "CRITICAL",
                        "score_risque": risk_score,
                        "username": username,
                        "source_ip": ip,
                        "host": host,
                        "statut": "ouvert",
                        "mitre_tactic": "credential_access",
                        "mitre_technique_id": "T1078",  # Valid Accounts abuse
                        "ueba_context": anomaly_res,
                        "created_at": now.isoformat(),
                    }

                    # Exécution automatique du playbook SOAR de désactivation de compte
                    # sous politique fail-closed stricte
                    soar_result = await execute_playbook(
                        self.es,
                        playbook_name="disable_account",
                        alert=alert_payload
                    )
                    
                    logger.info(
                        "SOAR Playbook 'disable_account' execution result for '%s': status=%s",
                        username, soar_result.get("status")
                    )

            except Exception as exc:
                logger.error("Error processing UEBA cycle for user '%s': %s", username, exc, exc_info=True)


def _build_es() -> AsyncElasticsearch:
    kwargs: Dict[str, Any] = {
        "hosts": [settings.ELASTICSEARCH_HOST],
        "basic_auth": (settings.ELASTICSEARCH_USERNAME, settings.ELASTICSEARCH_PASSWORD),
        "verify_certs": settings.ELASTICSEARCH_TLS_VERIFY,
        "request_timeout": settings.ELASTICSEARCH_REQUEST_TIMEOUT,
        "max_retries": settings.ELASTICSEARCH_MAX_RETRIES,
        "retry_on_timeout": True,
    }
    if settings.ELASTICSEARCH_CA_CERTS:
        kwargs["ca_certs"] = settings.ELASTICSEARCH_CA_CERTS
    return AsyncElasticsearch(**kwargs)


async def main() -> None:
    es = _build_es()
    engine = UEBAEngine(es)
    poll_interval = int(getattr(settings, "UEBA_POLL_SECONDS", 120))
    logger.info("UEBA Engine started (poll interval = %d s)", poll_interval)
    try:
        while True:
            try:
                await engine.run_cycle()
            except Exception as exc:
                logger.error("Error in UEBA engine loop: %s", exc)
            await asyncio.sleep(poll_interval)
    finally:
        await es.close()


if __name__ == "__main__":
    asyncio.run(main())
