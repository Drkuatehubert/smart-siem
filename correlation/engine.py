"""
correlation/engine.py — Moteur de corrélation principal
Couche 5 : Intelligence & Détection
Exigences : RF-COR-01 à RF-COR-06
"""
import asyncio
import json
import logging
import os
from datetime import datetime, timezone

from elasticsearch import AsyncElasticsearch
from rule_loader import load_rules
from evaluators.threshold import ThresholdEvaluator
from evaluators.sequential import SequentialEvaluator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("correlation")

ES_HOST = os.getenv("ELASTICSEARCH_HOST", "http://elasticsearch:9200")
ES_USER = os.getenv("ELASTICSEARCH_USERNAME", "elastic")
ES_PASS = os.getenv("ELASTICSEARCH_PASSWORD", "changeme")
POLL_INTERVAL = int(os.getenv("CORRELATION_POLL_SECONDS", 5))


async def create_alert(es: AsyncElasticsearch, rule: dict, matched_log_ids: list, niveau: str):
    """Crée une alerte dans idx-alerts quand une règle se déclenche."""
    now = datetime.now(timezone.utc).isoformat()
    alert = {
        "rule_id": rule.get("id"),
        "log_refs": matched_log_ids,
        "niveau": niveau,
        "statut": "ouvert",
        "score_risque": {"INFO": 20, "WARNING": 40, "HIGH": 70, "CRITICAL": 90}.get(niveau, 50),
        "created_at": now,
        "updated_at": now,
    }
    result = await es.index(index="idx-alerts", document=alert)
    logger.info("🚨 Alerte créée [%s] règle=%s id=%s", niveau, rule.get("nom"), result["_id"])
    return result["_id"]


async def run_correlation_cycle(es: AsyncElasticsearch, rules: list):
    """Évalue toutes les règles actives sur les logs récents."""
    for rule in rules:
        if not rule.get("active", True):
            continue
        try:
            if rule.get("type") == "seuil":
                evaluator = ThresholdEvaluator(es)
            else:
                evaluator = SequentialEvaluator(es)

            matched, log_ids = await evaluator.evaluate(rule)
            if matched:
                await create_alert(es, rule, log_ids, rule.get("niveau_alerte_genere", "HIGH"))
        except Exception as e:
            logger.error("Erreur évaluation règle %s : %s", rule.get("nom"), e)


async def main():
    es = AsyncElasticsearch(hosts=[ES_HOST], basic_auth=(ES_USER, ES_PASS), verify_certs=False)
    logger.info("Moteur de corrélation démarré")

    while True:
        try:
            rules = await load_rules(es)
            await run_correlation_cycle(es, rules)
        except Exception as e:
            logger.error("Cycle de corrélation : %s", e)
        await asyncio.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
