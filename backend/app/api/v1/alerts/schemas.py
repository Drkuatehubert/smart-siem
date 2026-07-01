"""alerts/schemas.py"""
from typing import Optional, List
from pydantic import BaseModel

class AlertOut(BaseModel):
    id: str
    rule_id: Optional[str] = None
    log_refs: List[str] = []
    niveau: str  # INFO / WARNING / HIGH / CRITICAL
    statut: str  # ouvert / en_cours / resolu
    assigned_to: Optional[str] = None
    score_risque: Optional[int] = None
    created_at: str
    updated_at: str
    commentaires: Optional[str] = None

class AlertStatusUpdate(BaseModel):
    statut: str
    assigned_to: Optional[str] = None
    commentaires: Optional[str] = None

class AlertListResponse(BaseModel):
    total: int
    page: int
    size: int
    results: List[AlertOut]
