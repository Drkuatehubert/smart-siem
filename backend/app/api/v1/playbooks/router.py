from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.v1.playbooks.service import (
    create_playbook,
    get_playbook_by_id,
    list_playbooks,
    trigger_playbook,
)
from app.core.audit import write_audit_log
from app.core.rbac import require_any_role, require_permission

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])


class PlaybookCreate(BaseModel):
    name: str
    description: str = ""
    action_type: str
    execution_mode: str = "CONFIRM"
    parameters: dict = {}
    target_type: Optional[str] = None
    confirmation_timeout_seconds: int = 300
    rollback_supported: bool = False
    is_active: bool = True


@router.get("", response_model=List[dict[str, Any]])
async def get_playbooks(_=Depends(require_any_role)):
    return await list_playbooks()


@router.post("", status_code=201, response_model=dict[str, Any])
async def create_playbook_route(
    body: PlaybookCreate,
    _=Depends(require_any_role),
):
    try:
        return await create_playbook(body.model_dump())
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/{playbook_id}", response_model=dict[str, Any])
async def get_playbook(
    playbook_id: str,
    _=Depends(require_any_role),
):
    pb = await get_playbook_by_id(playbook_id)
    if pb is None:
        raise HTTPException(status_code=404, detail="Playbook introuvable")
    return pb


@router.post("/{playbook_id}/trigger", status_code=202)
async def trigger(
    playbook_id: str,
    current_user=Depends(require_permission("playbooks:execute")),
):
    result = await trigger_playbook(playbook_id, current_user["sub"])
    await write_audit_log(
        user_id=current_user["sub"],
        action="playbook_executed",
        target_entity="playbook",
        target_id=playbook_id,
    )
    return result
