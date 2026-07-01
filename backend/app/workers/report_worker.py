"""
workers/report_worker.py
Génère automatiquement un rapport de sécurité chaque lundi à 00:00.
Utilise APScheduler pour la planification.
"""
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from app.reports.services import generate_report
from app.reports.models import ReportGenerateRequest, ReportType
from datetime import datetime, timedelta
import logging

logger = logging.getLogger("report_worker")


class ReportScheduler:
    def __init__(self):
        self.scheduler = AsyncIOScheduler()

    def start(self):
        # Rapport hebdomadaire : chaque lundi à 00:00
        self.scheduler.add_job(
            self._generate_weekly_report,
            trigger=CronTrigger(day_of_week="mon", hour=0, minute=0),
            id="weekly_report",
            replace_existing=True
        )
        self.scheduler.start()
        logger.info("ReportScheduler démarré — rapport hebdomadaire planifié")

    async def _generate_weekly_report(self):
        now   = datetime.utcnow()
        start = now - timedelta(days=7)
        try:
            req = ReportGenerateRequest(
                start_date=start,
                end_date=now,
                report_type=ReportType.WEEKLY,
                triggered_by="scheduler"
            )
            result = await generate_report(req)
            logger.info(f"Rapport hebdomadaire généré: {result['report_id']}")
        except Exception as e:
            logger.error(f"Échec génération rapport: {e}")