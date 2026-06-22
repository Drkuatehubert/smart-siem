"""
router.py — Endpoints du journal d'audit
Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-03 — Admin et Auditeur uniquement
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query

from app.core.rbac import require_admin
from app.api.v1.audit.schemas import AuditLogOut, AuditLogListResponse
from app.api.v1.audit.service import get_audit_logs

router = APIRouter(prefix="/audit", tags=["Journal d'Audit"])


@router.get(
    "/logs",
    response_model=AuditLogListResponse,
    summary="Journal d'audit complet",
    description="Consulte toutes les actions utilisateurs. Réservé Administrateur.",
)
async def list_audit_logs(
    user_id: Optional[str] = Query(None, description="Filtrer par utilisateur"),
    action: Optional[str] = Query(None, description="Type d'action : connexion, deconnexion, etc."),
    from_date: Optional[str] = Query(None, description="Date début ISO8601"),
    to_date: Optional[str] = Query(None, description="Date fin ISO8601"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    current_user: dict = Depends(require_admin),
):
    return await get_audit_logs(
        user_id=user_id,
        action=action,
        from_date=from_date,
        to_date=to_date,
        page=page,
        size=size,
    )
