from fastapi import APIRouter, Depends
from app.api.v1.dashboard.schemas import DashboardSummary
from app.api.v1.dashboard.service import get_summary
from app.core.rbac import require_any_role
router = APIRouter(prefix="/dashboard", tags=["Dashboard"])
@router.get("/summary", response_model=DashboardSummary)
async def summary(_=Depends(require_any_role)):
    return await get_summary()
