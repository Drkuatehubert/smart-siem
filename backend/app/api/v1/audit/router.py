"""
router.py â€” Endpoints du journal d'audit (durcis)

Responsable : Chef de Projet & SÃ©curitÃ©
Exigences : RF-SEC-03 â€” Admin et Auditeur (lecture seule)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from app.core.rbac import require_auditor
from app.api.v1.audit.schemas import (
    AuditExportRequest,
    AuditLogListResponse,
    FailedLoginsResponse,
)
from app.api.v1.audit.service import (
    export_audit_logs,
    get_audit_logs,
    get_failed_logins,
)

router = APIRouter(prefix="/audit", tags=["Journal d'Audit"])


@router.get(
    "/logs",
    response_model=AuditLogListResponse,
    summary="Journal d'audit complet",
    description="Consulte toutes les actions utilisateurs. Admin et Auditeur uniquement.",
)
async def list_audit_logs(
    user_id: Optional[str] = Query(None, max_length=64),
    action: Optional[str] = Query(None, max_length=64),
    from_date: Optional[str] = Query(None),
    to_date: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    _user: dict = Depends(require_auditor),
):
    return await get_audit_logs(user_id, action, from_date, to_date, page, size)


@router.get(
    "/failed-logins",
    response_model=FailedLoginsResponse,
    summary="Ã‰checs de connexion",
    description="AgrÃ¨ge les `connexion_echouee` et `compte_verrouille`.",
)
async def list_failed_logins(
    from_date: Optional[str] = Query(None),
    to_date: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=500),
    _user: dict = Depends(require_auditor),
):
    res = await get_failed_logins(from_date, to_date, page, size)
    return FailedLoginsResponse(
        total=res["total"],
        from_date=res.get("from_date"),
        to_date=res.get("to_date"),
        results=res["results"],
    )


@router.get(
    "/logs/export",
    summary="Export streaming du journal d'audit (CSV/JSONL)",
    description="Renvoie un flux streaming â€” la lecture n'est pas paginÃ©e cÃ´tÃ© client.",
)
async def export_logs(
    format: str = Query("csv", pattern=r"^(csv|jsonl)$"),
    from_date: Optional[str] = Query(None),
    to_date: Optional[str] = Query(None),
    max_rows: int = Query(50_000, ge=1, le=100_000),
    _user: dict = Depends(require_auditor),
):
    media_type = "text/csv" if format == "csv" else "application/x-ndjson"
    filename = f"audit-log.{format}"

    async def _gen():
        async for chunk in export_audit_logs(format, from_date, to_date, max_rows):
            yield chunk

    return StreamingResponse(
        _gen(),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
