from fastapi import APIRouter, Depends, Query
from uuid import UUID
from typing import Optional
from app.core.rbac import get_current_user, require_permission, CurrentUser
from app.playbook import services
from app.playbook.models import ExecutePlaybookRequest

router = APIRouter(prefix="/api/v1/playbooks", tags=["Playbooks"])


@router.post("/execute")
@require_permission("playbooks", "execute")
async def execute_playbook(
    req: ExecutePlaybookRequest,
    current_user: CurrentUser = Depends(get_current_user)
):
    """
    Exécution MANUELLE d'un playbook.
    L'exécution automatique passe par alert_worker.py.
    Le corps de la requête contient les params spécifiques au type de playbook.
    """
    return await services.execute_playbook(req, current_user, triggered_by="manual")


@router.get("")
@require_permission("playbooks", "read")
async def list_playbooks(
    playbook_type: Optional[str] = Query(None),
    is_active:     Optional[bool] = Query(None),
    current_user: CurrentUser = Depends(get_current_user)
):
    pool = await services.get_pool()
    async with pool.acquire() as conn:
        conditions = ["1=1"]
        params = []
        if playbook_type:
            conditions.append(f"playbook_type = $1")
            params.append(playbook_type)
        if is_active is not None:
            conditions.append(f"is_active = ${len(params)+1}")
            params.append(is_active)
        rows = await conn.fetch(
            f"SELECT * FROM playbooks WHERE {' AND '.join(conditions)}", *params
        )
    return [dict(r) for r in rows]


@router.get("/{playbook_id}/executions")
@require_permission("playbooks", "read")
async def get_playbook_executions(
    playbook_id: UUID,
    current_user: CurrentUser = Depends(get_current_user)
):
    pool = await services.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT * FROM playbook_executions
            WHERE playbook_id = $1
            ORDER BY started_at DESC LIMIT 100
            """,
            playbook_id
        )
    return [dict(r) for r in rows]