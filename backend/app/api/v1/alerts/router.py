"""alerts/router.py"""
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.v1.alerts.schemas import AlertListResponse, AlertOut, AlertStatusUpdate
from app.api.v1.alerts.service import (
    acknowledge_alert,
    get_alert,
    list_alerts,
    update_alert_status,
)
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


@router.patch("/{alert_id}/acknowledge", summary="Acquitter une alerte")
async def acknowledge(
    alert_id: str,
    current_user: dict = Depends(require_permission("alerts:update")),
):
    result = await acknowledge_alert(alert_id, current_user["sub"])
    await write_audit_log(
        current_user["sub"],
        "traitement_alerte",
        target_entity="alerte",
        target_id=alert_id,
        details={"action": "acknowledge"},
    )
    return result


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


@router.post("/{alert_id}/trigger-soar", summary="Déclencher manuellement le SOAR")
async def trigger_soar_manual(
    alert_id: str,
    current_user: dict = Depends(require_permission("alerts:update")),
):
    from app.core.postgres import get_pg_pool
    from app.core.redis_client import get_redis_client

    # 1. Lire l'alerte depuis PostgreSQL
    try:
        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """SELECT a.id, a.title, a.level, a.source_ips, a.affected_hosts,
                          r.name AS rule_name
                   FROM alerts a
                   LEFT JOIN correlation_rules r ON a.rule_id = r.id
                   WHERE a.id = $1::uuid""",
                alert_id,
            )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur PG : {exc}")

    if not row:
        raise HTTPException(status_code=404, detail="Alerte introuvable")

    # 2. Parser source_ips (JSONB → list)
    source_ips_raw = row["source_ips"] or []
    if isinstance(source_ips_raw, str):
        try:
            source_ips_raw = json.loads(source_ips_raw)
        except Exception:
            source_ips_raw = []

    # 3. Publier dans Redis soar_alerts
    payload = json.dumps({
        "alert_id":   str(row["id"]),
        "level":      row["level"] or "INFO",
        "rule_name":  row["rule_name"] or "",
        "source_ips": source_ips_raw,
        "source_ip":  source_ips_raw[0] if source_ips_raw else "",
        "title":      row["title"] or "",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
    })
    try:
        r = get_redis_client()
        await r.lpush("soar_alerts", payload)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Redis erreur : {exc}")

    await write_audit_log(
        current_user["sub"],
        "soar_manuel",
        target_entity="alerte",
        target_id=alert_id,
        details={"source_ips": source_ips_raw},
    )
    return {"status": "triggered", "alert_id": alert_id}
