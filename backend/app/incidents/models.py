from __future__ import annotations

from pydantic import BaseModel, Field


class Incident(BaseModel):
    # Modèle simplifié de démo (comparer à IncidentOut dans api/v1/incidents/schemas.py,
    # le modèle complet réellement branché sur Elasticsearch).
    id: str
    title: str
    severity: str = Field(default="medium")
    status: str = Field(default="open")


class IncidentFilter(BaseModel):
    severity: str | None = None
    status: str | None = None
