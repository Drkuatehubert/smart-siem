# Regroupe les tâches de fond (encore à l'état de squelette) pour un import simplifié,
# ex: `from app.workers import alert_worker`.
from app.workers.alert_worker import alert_worker
from app.workers.report_worker import report_worker
from app.workers.ueba_scheduler import ueba_scheduler

__all__ = ["alert_worker", "report_worker", "ueba_scheduler"]
