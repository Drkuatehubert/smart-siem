from typing import Any, List

from fastapi import APIRouter, Depends

from app.api.v1.playbooks.service import list_playbooks
from app.core.rbac import require_any_role

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])


@router.get("", response_model=List[dict[str, Any]])
async def get_playbooks(_=Depends(require_any_role)):
    return await list_playbooks()
