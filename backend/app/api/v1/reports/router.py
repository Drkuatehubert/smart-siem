from fastapi import APIRouter, Depends
from app.api.v1.reports.schemas import ReportRequest, ReportOut
from app.core.rbac import require_permission
router = APIRouter(prefix="/reports", tags=["Rapports"])
@router.post("/generate", response_model=ReportOut, status_code=202)
async def generate(body: ReportRequest, _=Depends(require_permission("reports:generate"))):
    return {"id": "report-placeholder", "status": "queued", "download_url": None}
