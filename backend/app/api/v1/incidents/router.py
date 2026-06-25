from fastapi import APIRouter, Depends, Query
from app.api.v1.incidents.schemas import IncidentCreate, IncidentListResponse
from app.api.v1.incidents.service import list_incidents, create_incident
from app.core.rbac import require_permission
router = APIRouter(prefix="/incidents", tags=["Incidents"])
@router.get("", response_model=IncidentListResponse)
async def get_incidents(page: int = 1, size: int = 50, _=Depends(require_permission("incidents:read"))):
    return await list_incidents(page, size)
@router.post("", status_code=201)
async def create(body: IncidentCreate, current_user=Depends(require_permission("incidents:create"))):
    return await create_incident(body.model_dump(), current_user["sub"])
