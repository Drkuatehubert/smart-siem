from fastapi import APIRouter, Depends
from app.api.v1.reports.schemas import ReportRequest, ReportOut
from app.core.rbac import require_permission
router = APIRouter(prefix="/reports", tags=["Rapports"])
@router.post("/generate", response_model=ReportOut, status_code=202)
async def generate(body: ReportRequest, _=Depends(require_permission("reports:generate"))):
    # 202 Accepted : la génération réelle n'est pas encore implémentée (voir service.py),
    # on renvoie donc un id de substitution avec le statut "queued" (mis en file d'attente).
    return {"id": "report-placeholder", "status": "queued", "download_url": None}
