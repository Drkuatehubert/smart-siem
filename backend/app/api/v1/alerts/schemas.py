"""alerts/schemas.py"""
from typing import Optional, List
from pydantic import BaseModel


class AlertOut(BaseModel):
    id: str                              # ES _id
    pg_alert_id: Optional[str] = None   # UUID PostgreSQL (depuis alert-mirror)
    level: str                           # INFO / WARNING / HIGH / CRITICAL
    status: str                          # open / investigating / confirmed / closed
    title: Optional[str] = None
    rule_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    source_ips: Optional[List[str]] = []
    affected_hosts: Optional[List[str]] = []
    confidence_score: Optional[int] = None
    triggered_at: Optional[str] = None  # @timestamp depuis alert-mirror


class AlertStatusUpdate(BaseModel):
    status: str
    assigned_to: Optional[str] = None
    commentaires: Optional[str] = None


class AlertListResponse(BaseModel):
    total: int
    page: int
    size: int
    results: List[AlertOut]
