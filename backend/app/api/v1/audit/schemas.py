"""schemas.py – Schémas Pydantic pour le journal d'audit."""
from __future__ import annotations

from typing import Any, List, Literal, Optional

from pydantic import BaseModel, Field


class AuditLogOut(BaseModel):
    id: str
    performed_at: Optional[str] = None
    user_id: Optional[str] = None
    username: Optional[str] = None
    role_snapshot: Optional[str] = None
    action: str
    result: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    metadata: Optional[Any] = None


class AuditLogListResponse(BaseModel):
    total: int
    page: int
    size: int
    results: List[AuditLogOut]


class AuditExportRequest(BaseModel):
    format: Literal["csv", "jsonl"] = "csv"
    from_date: Optional[str] = None
    to_date: Optional[str] = None
    max_rows: int = Field(default=50_000, ge=1, le=100_000)


class FailedLoginsResponse(BaseModel):
    total: int
    from_date: Optional[str] = None
    to_date: Optional[str] = None
    results: List[AuditLogOut]
