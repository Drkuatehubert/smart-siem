"""alerts/router.py"""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from app.api.v1.alerts.schemas import AlertListResponse, AlertStatusUpdate
from app.api.v1.alerts.service import list_alerts, update_alert_status
from app.core.rbac import require_permission, require_any_role
from app.api.v1.auth.service import write_audit_log

router = APIRouter(prefix="/alerts", tags=["Alertes"])

@router.get("", response_model=AlertListResponse, summary="Liste des alertes")
async def get_alerts(
    niveau: Optional[str] = Query(None),
    statut: Optional[str] = Query(None),
    page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(require_permission("alerts:read"))
):
    org_scope = current_user.get("org_scope")
    result = await list_alerts(niveau, statut, page, size, org_scope)
    await write_audit_log(current_user["sub"], "consultation_alerte", details={"filters": {"niveau": niveau, "statut": statut}})
    return result

@router.patch("/{alert_id}/status", summary="Mettre à jour le statut d'une alerte")
async def update_status(
    alert_id: str, body: AlertStatusUpdate,
    current_user: dict = Depends(require_permission("alerts:update"))
):
    result = await update_alert_status(alert_id, body.statut, body.assigned_to, body.commentaires)
    await write_audit_log(current_user["sub"], "traitement_alerte", target_entity="alerte", target_id=alert_id)
    return result
