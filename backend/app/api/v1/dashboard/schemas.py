from typing import Any, Dict, List

from pydantic import BaseModel


class AlertSummary(BaseModel):
    niveau: str
    count: int


class DashboardSummary(BaseModel):
    total_logs_24h: int
    total_alerts_open: int
    critical_alerts: int = 0
    alerts_by_level: List[AlertSummary]
    log_volume_by_hour: List[Dict[str, Any]]
    event_actions: List[str] = []
