from fastapi import APIRouter, Depends

from app.api.v1.rules.schemas import RuleCreate, RuleListResponse
from app.api.v1.rules.service import create_rule, delete_rule, list_rules, toggle_rule
from app.core.rbac import require_admin, require_permission, require_analyste

router = APIRouter(prefix="/rules", tags=["Règles de Corrélation"])


@router.get("", response_model=RuleListResponse)
async def get_rules(
    page: int = 1,
    size: int = 50,
    _=Depends(require_permission("rules:read")),
):
    return await list_rules(page, size)


@router.post("", status_code=201)
async def create(body: RuleCreate, current_user=Depends(require_admin)):
    return await create_rule(body.model_dump(), current_user["sub"])


@router.patch("/{rule_id}/toggle")
async def toggle(rule_id: str, _=Depends(require_analyste)):
    return await toggle_rule(rule_id)


@router.delete("/{rule_id}", status_code=204)
async def delete(rule_id: str, _=Depends(require_admin)):
    await delete_rule(rule_id)
