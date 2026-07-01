from __future__ import annotations

from fastapi import APIRouter

from app.incidents.models import Incident, IncidentFilter
from app.incidents.services import list_incidents

# ATTENTION : module de démo (données figées, filtrage en mémoire, pas de RBAC).
# Le router réellement utilisé en production est api/v1/incidents/router.py.
router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("", response_model=list[Incident])
async def get_incidents(filters: IncidentFilter | None = None) -> list[Incident]:
    incidents = await list_incidents()
    # Filtrage appliqué en mémoire (après récupération) puisque la source de données
    # est une liste fixe et non une vraie requête Elasticsearch filtrée.
    if filters:
        if filters.severity:
            incidents = [incident for incident in incidents if incident.severity == filters.severity]
        if filters.status:
            incidents = [incident for incident in incidents if incident.status == filters.status]
    return incidents
