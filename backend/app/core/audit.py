from __future__ import annotations

from typing import Any

from app.api.v1.auth.service import write_audit_log


async def log_action(
    *,
    user_id: str | None = None,
    action: str,
    details: dict[str, Any] | None = None,
    status: str = "success",
) -> None:
    # Petite fonction de confort qui enveloppe `write_audit_log` (défini dans
    # auth/service.py) avec une signature plus courte, pour les appelants qui
    # n'ont pas besoin de préciser ip_address/user_agent/request_id/etc.
    await write_audit_log(user_id=user_id, action=action, status=status, details=details or {})
