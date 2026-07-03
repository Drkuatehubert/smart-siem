from fastapi import APIRouter, Depends
from typing import Any, List
from app.api.v1.incidents.schemas import IncidentCreate
from app.api.v1.incidents.service import list_incidents, create_incident
from app.core.rbac import require_permission
router = APIRouter(prefix="/incidents", tags=["Incidents"])
@router.get("", response_model=List[dict[str, Any]])
async def get_incidents(_=Depends(require_permission("incidents:read"))):
    return await list_incidents()
@router.post("", status_code=201)
async def create(body: IncidentCreate, current_user=Depends(require_permission("incidents:create"))):
    # current_user["sub"] (identifiant JWT de l'appelant) devient le propriétaire de l'incident créé.
    return await create_incident(body.model_dump(), current_user["sub"])
