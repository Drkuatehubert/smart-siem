"""
correlation/engine.py â€” Moteur de corrÃ©lation principal (durci)

Couche 5 : Intelligence & DÃ©tection
Exigences : RF-COR-01 Ã  RF-COR-06, NFR-SEC-05 (pas de creds en dur, pas de verify_certs=False)

AmÃ©liorations :
  * imports absolus (`from correlation.â€¦`) pour fonctionner en container ;
  * configuration via `app.config.settings` (pas d'env direct) ;
  * cap `size` dans les requÃªtes seuils ;
  * `run_correlation_cycle` accepte un pool de rÃ¨gles et logge le nombre Ã©valuÃ© ;
  * `create_alert` enregistre aussi `mitre_technique_id` (cohÃ©rence avec SOAR).
"""

from __future__ import annotations

import asyncio
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# Permet l'import des modules `app.*` (config, etc.) depuis ce conteneur
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from elasticsearch import AsyncElasticsearch  # noqa: E402

from app.config import settings  # noqa: E402
from correlation.evaluators.cross_source import CrossSourceEvaluator  # noqa: E402
from correlation.evaluators.sequential import SequentialEvaluator  # noqa: E402
from correlation.evaluators.threshold import ThresholdEvaluator  # noqa: E402
from correlation.evaluators.statistical import StatisticalEvaluator  # noqa: E402
from correlation.rule_loader import load_rules  # noqa: E402

logger = logging.getLogger("correlation")
logging.basicConfig(level=logging.INFO)


# Mapping niveau â†’ score de risque
_RISK_SCORE = {"INFO": 20, "WARNING": 40, "HIGH": 70, "CRITICAL": 90}


async def create_alert(
    es: AsyncElasticsearch,
    rule: Dict[str, Any],
    matched_log_ids: List[str],
    niveau: str,
) -> str:
    """CrÃ©e une alerte dans `idx-alerts` quand une rÃ¨gle se dÃ©clenche."""
    now = datetime.now(timezone.utc).isoformat()
    alert = {
        "rule_id": rule.get("id"),
        "rule_nom": rule.get("nom"),
        "log_refs": matched_log_ids,
        "niveau": niveau,
        "mitre_tactic": rule.get("mitre_tactic"),
        "mitre_technique_id": rule.get("mitre_technique_id"),
        "kill_chain_phase": rule.get("kill_chain_phase"),
        "statut": "ouvert",
        "score_risque": _RISK_SCORE.get(niveau, 50),
        "soar_recommended": rule.get("niveau_alerte_genere") == "CRITICAL",
        "soar_approved": False,
        "ueba_context": rule.get("ueba_context", {}),
        "created_at": now,
        "updated_at": now,
    }
    res = await es.index(index="idx-alerts", document=alert)
    logger.info(
        "ðŸš¨ Alerte [%s] rÃ¨gle=%s id=%s (MITRE %s)",
        niveau, rule.get("nom"), res["_id"], rule.get("mitre_technique_id"),
    )
    return res["_id"]


async def run_correlation_cycle(es: AsyncElasticsearch, rules: List[Dict[str, Any]]) -> int:
    """Ã‰value toutes les rÃ¨gles actives sur les logs rÃ©cents. Renvoie le nb d'alertes crÃ©Ã©es."""
    alerts_created = 0
    for rule in rules:
        if not rule.get("active", True):
            continue
        try:
            if rule.get("type") == "seuil":
                evaluator = ThresholdEvaluator(es)
            elif rule.get("type") == "cross_source":
                evaluator = CrossSourceEvaluator(es)
            elif rule.get("type") == "statistical":
                evaluator = StatisticalEvaluator(es)
            else:
                evaluator = SequentialEvaluator(es)

            matched, log_ids = await evaluator.evaluate(rule)
            if matched:
                await create_alert(
                    es, rule, log_ids, rule.get("niveau_alerte_genere", "HIGH"),
                )
                alerts_created += 1
        except Exception as exc:
            logger.error(
                "Erreur Ã©valuation rÃ¨gle %s (id=%s) : %s",
                rule.get("nom"), rule.get("id"), exc,
            )
    return alerts_created


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
    logger.info("Moteur de corrÃ©lation dÃ©marrÃ© (poll=%ss)", settings.CORRELATION_POLL_SECONDS)
    try:
        while True:
            try:
                rules = await load_rules(es)
                n = await run_correlation_cycle(es, rules)
                if n:
                    logger.info("Cycle : %d alerte(s) crÃ©Ã©e(s) sur %d rÃ¨gle(s)", n, len(rules))
            except Exception as exc:
                logger.error("Cycle de corrÃ©lation : %s", exc)
            await asyncio.sleep(settings.CORRELATION_POLL_SECONDS)
    finally:
        await es.close()


if __name__ == "__main__":
    asyncio.run(main())
