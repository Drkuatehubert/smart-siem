from fastapi import APIRouter, Depends
from app.api.v1.sources.schemas import SourceCreate, SourceListResponse
from app.api.v1.sources.service import list_sources, create_source
from app.core.rbac import require_permission, require_admin
router = APIRouter(prefix="/sources", tags=["Sources"])
@router.get("", response_model=SourceListResponse)
async def get_sources(page: int = 1, size: int = 50, _=Depends(require_permission("sources:read"))):
    return await list_sources(page, size)
@router.post("", status_code=201)
async def create(body: SourceCreate, _=Depends(require_admin)):
    return await create_source(body.model_dump())
