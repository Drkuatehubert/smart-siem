"""
workers/alert_worker.py

Rôle : tourne en boucle, scrute la table alerts PostgreSQL,
       identifie les alertes non résolues sans procédure en cours,
       déclenche automatiquement le playbook approprié.

Condition de déclenchement :
  - status NOT IN ('resolved', 'false_positive', 'investigating', 'contained')
  - Aucune playbook_execution en cours (PENDING ou RUNNING) liée à cette alerte
  - triggered_at > NOW() - INTERVAL configuré (évite les alertes très anciennes)

Ce worker est indépendant de correlation_engine et ueba_worker.
Il réagit à ce que ces modules ont écrit dans la table alerts.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from app.core.database import get_pool
from app.playbook.services import execute_playbook
from app.playbook.models import (
    ExecutePlaybookRequest, BlockIPParams,
    DisableAccountParams, EscalateParams
)
from app.config import settings

logger = logging.getLogger("alert_worker")


class AlertWorker:
    """
    Worker de surveillance des alertes.
    Lance execute_playbook() pour chaque alerte qualifiée.
    """

    def __init__(
        self,
        poll_interval_seconds: int = 30,   # Fréquence de scrutation
        lookback_hours: int = 24           # Ne traite que les alertes récentes
    ):
        self.poll_interval  = poll_interval_seconds
        self.lookback_hours = lookback_hours
        self._running       = False

    async def start(self):
        """Boucle principale — tourne jusqu'à stop()."""
        self._running = True
        logger.info(f"AlertWorker démarré (intervalle: {self.poll_interval}s)")
        while self._running:
            try:
                await self._process_pending_alerts()
            except Exception as e:
                logger.error(f"AlertWorker erreur: {e}")
            await asyncio.sleep(self.poll_interval)

    def stop(self):
        self._running = False

    async def _process_pending_alerts(self):
        """
        Identifie et traite les alertes qui nécessitent une action automatique.
        """
        pool   = await get_pool()
        cutoff = datetime.utcnow() - timedelta(hours=self.lookback_hours)

        async with pool.acquire() as conn:
            # Alertes sans procédure en cours
            pending = await conn.fetch(
                """
                SELECT a.*, p.id AS playbook_id, p.playbook_type,
                       p.default_params
                FROM alerts a
                -- Jointure avec la règle pour obtenir le playbook suggéré
                LEFT JOIN correlation_rules cr ON a.rule_id = cr.id
                LEFT JOIN playbooks p ON cr.playbook_id = p.id
                -- Vérifie qu'aucune exécution n'est en cours pour cette alerte
                WHERE a.status NOT IN (
                    'resolved', 'false_positive', 'investigating', 'contained'
                )
                AND a.triggered_at >= $1
                AND p.id IS NOT NULL           -- Il existe un playbook associé
                AND p.is_active = TRUE
                AND NOT EXISTS (
                    SELECT 1 FROM playbook_executions pe
                    WHERE pe.alert_id = a.id
                    AND pe.status IN ('pending', 'running')
                )
                ORDER BY
                    CASE a.level
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH'     THEN 2
                        WHEN 'WARNING'  THEN 3
                        ELSE 4
                    END,
                    a.triggered_at ASC
                LIMIT 50    -- Traite au max 50 alertes par cycle
                """,
                cutoff
            )

        if not pending:
            return

        logger.info(f"AlertWorker: {len(pending)} alerte(s) à traiter")

        for alert in pending:
            try:
                await self._trigger_playbook(dict(alert))
            except Exception as e:
                logger.error(f"Erreur traitement alerte {alert['id']}: {e}")

    async def _trigger_playbook(self, alert: dict):
        """Construit la requête d'exécution selon le type de playbook."""

        playbook_type = alert.get("playbook_type")
        source_ips    = alert.get("source_ips") or []
        usernames     = alert.get("usernames") or []

        # Construction des params selon le type
        req = ExecutePlaybookRequest(
            alert_id=alert["id"],
            playbook_id=alert["playbook_id"],
        )

        match playbook_type:
            case "block_ip":
                if source_ips:
                    req.block_ip_params = BlockIPParams(
                        ip_address=source_ips[0],
                        duration_hours=24
                    )
                else:
                    logger.warning(f"block_ip sans source_ip pour alerte {alert['id']}")
                    return

            case "disable_account":
                if usernames:
                    req.disable_account_params = DisableAccountParams(
                        username=usernames[0],
                        reason=f"Désactivation automatique — Alerte {alert['id']}"
                    )
                else:
                    return

            case "escalate":
                req.escalate_params = EscalateParams(
                    escalate_to=settings.DEFAULT_ESCALATION_EMAIL,
                    message=f"Alerte {alert['level']} — {alert['title']}"
                )

            case _:
                logger.warning(f"Type de playbook non géré: {playbook_type}")
                return

        result = await execute_playbook(req, user=None, triggered_by="auto_worker")
        logger.info(f"Playbook exécuté pour alerte {alert['id']}: {result['status']}")