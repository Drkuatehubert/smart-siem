from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from app.correlation_rules.models import CorrelationRule, RuleFilter, RuleToggleRequest
from app.correlation_rules.services import list_rules, toggle_rule

# ATTENTION : module de démo (données figées, pas de RBAC ni de persistance réelle).
# Le router réellement utilisé en production est api/v1/rules/router.py.
router = APIRouter(prefix="/correlation-rules", tags=["Correlation Rules"])


@router.get("", response_model=list[CorrelationRule])
async def get_rules(filters: RuleFilter | None = None) -> list[CorrelationRule]:
    rules = await list_rules()
    # Filtrage en mémoire (la source de données n'étant pas une vraie requête filtrable).
    if filters and filters.enabled is not None:
        rules = [rule for rule in rules if rule.enabled is filters.enabled]
    return rules


@router.patch("/{rule_id}/toggle")
async def toggle_rule_endpoint(rule_id: str, payload: RuleToggleRequest) -> CorrelationRule:
    return await toggle_rule(rule_id, payload.enabled)


@router.get("/{rule_id}", response_model=CorrelationRule)
async def get_rule(rule_id: str) -> CorrelationRule:
    # Pas de "get by id" direct côté service : on parcourt la liste complète et on
    # filtre ici (acceptable seulement parce que la liste est petite et figée).
    rules = await list_rules()
    for rule in rules:
        if rule.id == rule_id:
            return rule
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
