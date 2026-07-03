from typing import Any, List

from fastapi import APIRouter, Depends

from app.core.rbac import require_any_role

router = APIRouter(prefix="/compliance", tags=["Conformité"])


@router.get("", response_model=List[dict[str, Any]])
async def get_compliance(_=Depends(require_any_role)):
    return []
