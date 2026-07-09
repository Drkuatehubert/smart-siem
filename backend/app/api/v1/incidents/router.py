from __future__ import annotations

from pydantic import BaseModel
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException

from app.api.v1.incidents.schemas import IncidentCreate
from app.api.v1.incidents.service import (
    add_response_action,
    assign_incident,
    create_incident,
    get_incident,
    list_incidents,
    update_incident_status,
)
from app.core.audit import write_audit_log
from app.core.rbac import require_permission

router = APIRouter(prefix="/incidents", tags=["Incidents"])


class StatusUpdate(BaseModel):
    status: str
    user: Optional[str] = None
    role: Optional[str] = None


class AssignUpdate(BaseModel):
    assigned_to: str
    user: Optional[str] = None
    role: Optional[str] = None


class ActionCreate(BaseModel):
    action: str
    target: str
    by: str


@router.get("", response_model=List[dict[str, Any]])
async def get_incidents(_=Depends(require_permission("incidents:read"))):
    return await list_incidents()


@router.get("/{incident_id}")
async def get_incident_detail(
    incident_id: str,
    _=Depends(require_permission("incidents:read")),
):
    inc = await get_incident(incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident introuvable")
    return inc


@router.post("", status_code=201)
async def create(
    body: IncidentCreate,
    current_user=Depends(require_permission("incidents:create")),
):
    result = await create_incident(body.model_dump(), current_user["sub"])
    await write_audit_log(
        user_id=current_user["sub"],
        action="incident_created",
        target_entity="incident",
        target_id=str(result.get("id", "")),
        details={"title": body.title if hasattr(body, "title") else "", "severity": body.severity if hasattr(body, "severity") else ""},
    )
    return result


@router.patch("/{incident_id}/status")
async def update_status(
    incident_id: str,
    body: StatusUpdate,
    current_user=Depends(require_permission("incidents:update")),
):
    result = await update_incident_status(incident_id, body.status)
    action = "incident_resolved" if body.status in ("resolved", "closed") else "incident_assigned"
    await write_audit_log(
        user_id=current_user["sub"],
        action=action,
        target_entity="incident",
        target_id=incident_id,
        details={"status": body.status},
    )
    return result


@router.patch("/{incident_id}/assign")
async def assign(
    incident_id: str,
    body: AssignUpdate,
    current_user=Depends(require_permission("incidents:update")),
):
    result = await assign_incident(incident_id, body.assigned_to)
    await write_audit_log(
        user_id=current_user["sub"],
        action="incident_assigned",
        target_entity="incident",
        target_id=incident_id,
        details={"assigned_to": body.assigned_to},
    )
    return result


@router.post("/{incident_id}/actions", status_code=201)
async def add_action(
    incident_id: str,
    body: ActionCreate,
    _=Depends(require_permission("incidents:update")),
):
    return await add_response_action(incident_id, body.action, body.target, body.by)
