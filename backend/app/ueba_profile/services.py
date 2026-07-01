"""
ueba_profile/services.py

ueba_worker.py (DATA/) écrit dans la table ueba_profiles de PostgreSQL.
Le backend ne fait QUE lire cette table et déclencher le worker si demandé.
"""
import asyncio, subprocess
from app.core.database import get_pool
from app.core.rbac import CurrentUser
from app.ueba_profile.models import UEBAFilter
from app.config import settings


async def get_profiles(filters: UEBAFilter, user: CurrentUser) -> dict:
    """Récupère les profils UEBA depuis PostgreSQL avec filtres optionnels."""
    pool = await get_pool()
    conditions = ["1=1"]
    params = []
    idx = 1

    if filters.username:
        conditions.append(f"entity_name ILIKE ${idx}")
        params.append(f"%{filters.username}%"); idx += 1

    if filters.risk_score_min is not None:
        conditions.append(f"risk_score >= ${idx}")
        params.append(filters.risk_score_min); idx += 1

    if filters.risk_score_max is not None:
        conditions.append(f"risk_score <= ${idx}")
        params.append(filters.risk_score_max); idx += 1

    if filters.entity_type:
        conditions.append(f"entity_type = ${idx}")
        params.append(filters.entity_type); idx += 1

    if filters.has_anomaly:
        conditions.append("anomaly_count > 0")

    where = " AND ".join(conditions)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT *, COUNT(*) OVER() AS total
            FROM ueba_profiles
            WHERE {where}
            ORDER BY risk_score DESC
            LIMIT ${idx} OFFSET ${idx+1}
            """,
            *params, filters.page_size, (filters.page - 1) * filters.page_size
        )

    total = rows[0]["total"] if rows else 0
    return {"total": total, "items": [dict(r) for r in rows]}


async def trigger_ueba_worker(mode: str = "full") -> dict:
    """
    Déclenche le module DATA/ueba/ueba_worker.py.
    Peut être appelé manuellement (POST /ueba/run) ou par le scheduler mensuel.
    """
    # Lance le worker en subprocess non-bloquant
    proc = await asyncio.create_subprocess_exec(
        "python",
        f"{settings.UEBA_WORKER_PATH}/ueba_worker.py",
        f"--mode={mode}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    # On ne bloque pas — le worker tourne en arrière-plan
    return {
        "status":  "started",
        "pid":     proc.pid,
        "mode":    mode,
        "message": "UEBA worker démarré en arrière-plan"
    }