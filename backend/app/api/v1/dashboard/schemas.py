from typing import List
from pydantic import BaseModel
class AlertSummary(BaseModel):
    niveau: str; count: int
class LogVolumePoint(BaseModel):
    hour: str; count: int
class DashboardSummary(BaseModel):
    total_logs_24h: int; total_alerts_open: int
    alerts_by_level: List[AlertSummary]; log_volume_by_hour: List[LogVolumePoint]
