from __future__ import annotations

from pydantic import BaseModel, Field


class CorrelationRule(BaseModel):
    # Modèle simplifié de démo (comparer à RuleOut dans api/v1/rules/schemas.py,
    # le modèle complet réellement branché sur Elasticsearch).
    id: str
    name: str
    description: str | None = None
    enabled: bool = True


class RuleFilter(BaseModel):
    enabled: bool | None = None


class RuleToggleRequest(BaseModel):
    enabled: bool = Field(...)
