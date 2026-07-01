from __future__ import annotations

from app.incidents.models import Incident


async def list_incidents() -> list[Incident]:
    # Donnée figée codée en dur, à titre de démo. La vraie source (Elasticsearch,
    # avec pagination) est api/v1/incidents/service.py.
    return [Incident(id="incident-1", title="Suspicious outbound connection", severity="high", status="open")]
