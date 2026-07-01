from __future__ import annotations

from app.audit_logs.models import AuditLog


async def list_audit_logs(action: str | None = None, status: str | None = None) -> list[AuditLog]:
    # Implémentation "stub" : renvoie toujours une entrée factice unique, sans
    # interroger Elasticsearch. Pour la vraie lecture du journal d'audit (avec
    # pagination, filtres et export), voir api/v1/audit/service.py.
    return [AuditLog(id="audit-1", action=action or "login", status=status or "success")]
