from typing import Any, List

from fastapi import APIRouter, Depends

from app.api.v1.ueba.service import list_profiles
from app.core.rbac import require_any_role

router = APIRouter(prefix="/ueba", tags=["UEBA"])


@router.get("/profiles", response_model=List[dict[str, Any]])
async def get_profiles(_=Depends(require_any_role)):
    return await list_profiles()
