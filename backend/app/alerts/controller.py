from fastapi import APIRouter, Depends, Query, Body
from uuid import UUID
from typing import Optional
from datetime import datetime
from app.core.rbac import get_current_user, require_permission, CurrentUser
from app.alerts import services
from app.alerts.models import AlertFilter, AlertDetail, AlertLevel, AlertStatus

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


@router.get("")
@require_permission("alerts", "read")
async def list_alerts(
    # Tous les filtres sont optionnels — query params
    from_date:       Optional[datetime] = Query(None),
    to_date:         Optional[datetime] = Query(None),
    level:           Optional[AlertLevel]  = Query(None),
    status:          Optional[AlertStatus] = Query(None),
    source_ip:       Optional[str] = Query(None),
    dest_ip:         Optional[str] = Query(None),
    mitre_tactic:    Optional[str] = Query(None),
    username:        Optional[str] = Query(None),
    affected_host:   Optional[str] = Query(None),
    page:            int = Query(1, ge=1),
    page_size:       int = Query(50, le=200),
    current_user: CurrentUser = Depends(get_current_user)
):
    """
    Liste les alertes avec filtres optionnels.
    RLS appliqué automatiquement selon le rôle.
    """
    f = AlertFilter(
        from_date=from_date, to_date=to_date,
        level=level, status=status,
        source_ip=source_ip, dest_ip=dest_ip,
        mitre_tactic=mitre_tactic, username=username,
        affected_host=affected_host,
        page=page, page_size=page_size
    )
    return await services.list_alerts(f, current_user)


@router.get("/{alert_id}/detail", response_model=AlertDetail)
@require_permission("alerts", "read")
async def get_alert_detail(
    alert_id: UUID,
    current_user: CurrentUser = Depends(get_current_user)
):
    """
    Route composite enrichie :
    PostgreSQL(alert) + ES(logs) + PostgreSQL(rule) + PostgreSQL(playbook_executions)
    """
    return await services.get_alert_detail(alert_id, current_user)


@router.patch("/{alert_id}")
@require_permission("alerts", "write")
async def update_alert(
    alert_id: UUID,
    updates: dict = Body(...),
    current_user: CurrentUser = Depends(get_current_user)
):
    """Mise à jour partielle (statut, notes, faux positif...)."""
    return await services.update_alert(alert_id, updates, current_user)


@router.delete("/{alert_id}", status_code=204)
@require_permission("alerts", "delete")
async def delete_alert(
    alert_id: UUID,
    current_user: CurrentUser = Depends(get_current_user)
):
    """Suppression réservée à l'admin."""
    pool = await services.get_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM alerts WHERE id = $1", alert_id)