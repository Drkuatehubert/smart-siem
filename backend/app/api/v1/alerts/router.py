"""alerts/router.py"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.v1.alerts.schemas import AlertListResponse, AlertOut, AlertStatusUpdate
from app.api.v1.alerts.service import get_alert, list_alerts, update_alert_status
from app.api.v1.auth.service import write_audit_log
from app.core.rbac import require_permission

router = APIRouter(prefix="/alerts", tags=["Alertes"])


@router.get("", response_model=AlertListResponse, summary="Liste des alertes")
async def get_alerts(
    niveau: Optional[str] = Query(None),
    statut: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(require_permission("alerts:read")),
):
    # org_scope de l'utilisateur courant, jamais celui d'un paramètre de requête :
    # empêche un utilisateur de consulter les alertes d'une autre organisation
    # simplement en changeant un paramètre d'URL.
    org_scope = current_user.get("org_scope")
    result = await list_alerts(niveau, statut, page, size, org_scope)
    await write_audit_log(
        current_user["sub"],
        "consultation_alerte",
        details={"filters": {"niveau": niveau, "statut": statut}},
    )
    return result


@router.get("/{alert_id}", response_model=AlertOut, summary="Détail d'une alerte")
async def get_alert_detail(
    alert_id: str,
    current_user: dict = Depends(require_permission("alerts:read")),
):
    alert = await get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alerte introuvable")
    return alert


@router.patch("/{alert_id}/status", summary="Mettre à jour le statut d'une alerte")
async def update_status(
    alert_id: str,
    body: AlertStatusUpdate,
    current_user: dict = Depends(require_permission("alerts:update")),
):
    result = await update_alert_status(
        alert_id, body.status, body.assigned_to, body.commentaires
    )
    await write_audit_log(
        current_user["sub"],
        "traitement_alerte",
        target_entity="alerte",
        target_id=alert_id,
    )
    return result
