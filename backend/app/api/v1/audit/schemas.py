"""
schemas.py — Schémas Pydantic pour le journal d'audit
"""

from typing import Optional, List
from pydantic import BaseModel


class AuditLogOut(BaseModel):
    id: str
    user_id: str
    action: str  # connexion / deconnexion / creation_utilisateur / modification_role / consultation_alerte / traitement_alerte
    target_entity: Optional[str] = None
    target_id: Optional[str] = None
    ip_address: Optional[str] = None
    details: Optional[dict] = None
    created_at: str


class AuditLogListResponse(BaseModel):
    total: int
    page: int
    size: int
    results: List[AuditLogOut]
