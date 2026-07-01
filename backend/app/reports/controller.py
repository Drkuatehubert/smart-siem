from __future__ import annotations

from fastapi import APIRouter

from app.reports.models import Report, ReportFilter, ReportGenerateRequest
from app.reports.services import generate_report

# ATTENTION : module de démo (pas de RBAC, génération simulée). Le router
# réellement utilisé en production est api/v1/reports/router.py.
router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("", response_model=list[Report])
async def list_reports(filters: ReportFilter | None = None) -> list[Report]:
    # Liste figée à un seul élément, dont le format reflète simplement le filtre reçu.
    return [Report(id="report-1", title="Weekly report", format=filters.format if filters else "pdf")]


@router.post("/generate", response_model=Report)
async def generate(payload: ReportGenerateRequest) -> Report:
    return await generate_report(payload.title, payload.format)
