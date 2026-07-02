from typing import List

from fastapi import APIRouter, Depends

from app.api.v1.agents.schemas import AgentOut
from app.api.v1.agents.service import list_agents
from app.core.rbac import require_permission

router = APIRouter(prefix="/agents", tags=["Agents"])


@router.get("", response_model=List[AgentOut])
async def get_agents(_=Depends(require_permission("sources:read"))):
    return await list_agents()
