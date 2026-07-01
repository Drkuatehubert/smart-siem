from __future__ import annotations

from fastapi import APIRouter

from app.audit_logs.models import AuditFilter, AuditLog
from app.audit_logs.services import list_audit_logs

# Préfixe /audit-logs : module distinct (et non branché sur require_auditor) de
# l'API d'audit "réelle" exposée sous /api/v1/audit (voir api/v1/audit/router.py).
router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])


@router.get("", response_model=list[AuditLog])
async def get_audit_logs(filters: AuditFilter | None = None) -> list[AuditLog]:
    return await list_audit_logs(filters.action if filters else None, filters.status if filters else None)
