from __future__ import annotations

from pydantic import BaseModel, Field


class AuditLog(BaseModel):
    # Version simplifiée d'une entrée d'audit (comparer à AuditLogOut dans
    # api/v1/audit/schemas.py, qui est le modèle complet réellement utilisé en production).
    id: str
    action: str
    status: str = Field(default="success")


class AuditFilter(BaseModel):
    action: str | None = None
    status: str | None = None
