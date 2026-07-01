from typing import List
from pydantic import BaseModel
class AlertSummary(BaseModel):
    # Nombre d'alertes ouvertes pour un niveau de sévérité donné.
    niveau: str; count: int
class LogVolumePoint(BaseModel):
    # Un point de la courbe de volume de logs, une heure donnée.
    hour: str; count: int
class DashboardSummary(BaseModel):
    total_logs_24h: int; total_alerts_open: int
    alerts_by_level: List[AlertSummary]; log_volume_by_hour: List[LogVolumePoint]
