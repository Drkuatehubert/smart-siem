from typing import Any, List

from fastapi import APIRouter, Depends

from app.core.rbac import require_any_role

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.get("", response_model=List[dict[str, Any]])
async def get_threat_intel(_=Depends(require_any_role)):
    return []
