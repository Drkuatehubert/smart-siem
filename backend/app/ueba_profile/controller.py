from __future__ import annotations

from fastapi import APIRouter

from app.ueba_profile.models import UEBAFilter, UEBAProfile, UEBARunRequest
from app.ueba_profile.services import get_profiles, trigger_worker

# NOTE : comme playbook/controller.py, ce router n'a pas de dépendance RBAC —
# à sécuriser (ex: require_permission) avant tout déploiement en production,
# les profils UEBA étant des données sensibles sur le comportement des utilisateurs.
router = APIRouter(prefix="/ueba", tags=["UEBA"])


@router.get("/profiles", response_model=list[UEBAProfile])
async def profiles(filters: UEBAFilter | None = None) -> list[UEBAProfile]:
    profiles = await get_profiles()
    if filters and filters.min_risk_score is not None:
        profiles = [profile for profile in profiles if profile.risk_score >= filters.min_risk_score]
    return profiles


@router.post("/run")
async def run(payload: UEBARunRequest) -> dict[str, object]:
    return await trigger_worker(payload.scope)
