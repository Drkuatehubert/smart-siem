from fastapi import APIRouter, Depends
from app.api.v1.rules.schemas import RuleCreate, RuleListResponse
from app.api.v1.rules.service import list_rules, create_rule, delete_rule
from app.core.rbac import require_admin, require_permission
router = APIRouter(prefix="/rules", tags=["Règles de Corrélation"])
@router.get("", response_model=RuleListResponse)
async def get_rules(page: int = 1, size: int = 50, _=Depends(require_permission("rules:read"))):
    return await list_rules(page, size)
@router.post("", status_code=201)
async def create(body: RuleCreate, current_user=Depends(require_admin)):
    return await create_rule(body.model_dump(), current_user["sub"])
@router.delete("/{rule_id}", status_code=204)
async def delete(rule_id: str, _=Depends(require_admin)):
    await delete_rule(rule_id)
