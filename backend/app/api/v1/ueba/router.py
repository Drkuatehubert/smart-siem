from fastapi import APIRouter, BackgroundTasks, Depends

from app.api.v1.ueba.service import compute_profiles, list_profiles
from app.core.rbac import require_admin, require_any_role

router = APIRouter(prefix="/ueba", tags=["UEBA"])


@router.get("/profiles")
async def get_profiles(_=Depends(require_any_role)):
    return await list_profiles()


@router.post("/compute", status_code=202)
async def trigger_compute(
    background_tasks: BackgroundTasks,
    _=Depends(require_admin),
):
    """Déclenche le recalcul des profils UEBA en arrière-plan."""
    background_tasks.add_task(compute_profiles)
    return {"status": "computing", "message": "Recalcul des profils UEBA en cours..."}
