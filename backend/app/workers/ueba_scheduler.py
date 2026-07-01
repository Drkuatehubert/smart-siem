"""
workers/ueba_scheduler.py
Déclenche le module DATA/ueba/ueba_worker.py automatiquement le 1er de chaque mois.
Le déclenchement manuel est disponible via POST /api/v1/ueba/run.
"""
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from app.ueba_profile.services import trigger_ueba_worker
import logging

logger = logging.getLogger("ueba_scheduler")


class UEBAScheduler:
    def __init__(self):
        self.scheduler = AsyncIOScheduler()

    def start(self):
        # Le 1er de chaque mois à 02:00
        self.scheduler.add_job(
            trigger_ueba_worker,
            trigger=CronTrigger(day=1, hour=2, minute=0),
            id="monthly_ueba",
            replace_existing=True
        )
        self.scheduler.start()
        logger.info("UEBAScheduler démarré — analyse mensuelle planifiée le 1er du mois")