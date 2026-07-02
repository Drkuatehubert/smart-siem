"""
service.py â€” Logique mÃ©tier de gestion des utilisateurs (durcie)

Responsable : Chef de Projet & SÃ©curitÃ©
Exigences : RF-SEC-02, RF-SEC-04

Fonctions exposÃ©es :
  * list_users          â€” pagination (capÃ©e)
  * get_user_by_id      â€” fetch unique
  * create_user         â€” unicitÃ© username + hachage + insertion
  * update_user         â€” patch partiel (last-admin guard)
  * delete_user         â€” delete (last-admin guard)
  * set_user_active     â€” active/dÃ©sactive (utilisÃ© par SOAR disable_account)
  * count_active_admins â€” utilisÃ© par last-admin guard et dashboard
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status

from app.config import settings
from app.core.elasticsearch import get_es_client
from app.core.security import hash_password, verify_password
from app.core.rbac import Role

IDX = "idx-users"

# Champs sensibles â€” JAMAIS retournÃ©s en sortie
_SENSITIVE = {"password_hash", "password_history", "mfa_pending_secret"}


def _sanitize(doc: Dict[str, Any]) -> Dict[str, Any]:
    for k in _SENSITIVE:
        doc.pop(k, None)
    return doc


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Lecture
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async def list_users(page: int = 1, size: int = 50) -> Dict[str, Any]:
    """Liste paginÃ©e des utilisateurs. `size` bornÃ©e Ã  500."""
    size = max(1, min(size, 500))
    from app.core.postgres import get_pg_pool
    from app.core.pg_utils import serialize_row

    offset = (page - 1) * size
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id, username, email, role, mfa_enabled, org_scope, is_active,
                      last_login_at, failed_login_count, locked_until, created_at, created_by
               FROM users
               ORDER BY created_at DESC NULLS LAST
               LIMIT $1 OFFSET $2""",
            size,
            offset,
        )
        total = await conn.fetchval("SELECT COUNT(*) FROM users")
    return {
        "total": total,
        "page": page,
        "size": size,
        "results": [serialize_row(r) for r in rows],
    }


async def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    from app.core.postgres import get_pg_pool
    from app.core.pg_utils import serialize_row

    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT id, username, email, role, mfa_enabled, org_scope, is_active,
                      last_login_at, failed_login_count, locked_until, created_at, created_by
               FROM users WHERE id = $1::uuid""",
            user_id,
        )
    return serialize_row(row) if row else None


async def count_active_admins() -> int:
    from app.core.postgres import get_pg_pool

    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        return await conn.fetchval(
            """SELECT COUNT(*) FROM users
               WHERE is_active = true
                 AND LOWER(role) IN ('admin', 'administrateur')"""
        )


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Ã‰criture
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async def create_user(data: Dict[str, Any]) -> Dict[str, Any]:
    es = get_es_client()
    username = data["username"].lower()

    # UnicitÃ© username
    exists = await es.exists(index=IDX, id=username)
    if exists:
        raise HTTPException(status_code=409, detail="Nom d'utilisateur dÃ©jÃ  pris")

    raw_password = data.pop("password")
    doc: Dict[str, Any] = {
        **data,
        "username": username,
        "password_hash": hash_password(raw_password),
        "is_active": data.get("is_active", True),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_login_at": None,
        "locked_until": None,
        "must_reset_password": False,
        "password_history": [],
    }
    res = await es.index(index=IDX, id=username, document=doc, refresh="wait_for")
    return {"id": res["_id"], **_sanitize(doc)}


async def update_user(user_id: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    es = get_es_client()
    patch = {k: v for k, v in patch.items() if v is not None}

    # Garde "last admin" si on touche au rÃ´le admin ou Ã  is_active
    if "role_id" in patch or "is_active" in patch:
        current = await get_user_by_id(user_id)
        if not current:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable")
        was_admin_active = (current.get("role_id") == Role.ADMINISTRATEUR and current.get("is_active", True))
        will_be_admin_active = (
            patch.get("role_id", current.get("role_id")) == Role.ADMINISTRATEUR
            and patch.get("is_active", current.get("is_active", True))
        )
        if was_admin_active and not will_be_admin_active:
            count = await count_active_admins()
            if count <= 1:
                raise HTTPException(
                    status_code=409,
                    detail="Impossible de retirer le dernier administrateur actif",
                )

    if not patch:
        return await get_user_by_id(user_id)  # type: ignore[return-value]

    await es.update(index=IDX, id=user_id, doc=patch, refresh="wait_for")
    return await get_user_by_id(user_id)  # type: ignore[return-value]


async def delete_user(user_id: str) -> None:
    es = get_es_client()
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if user.get("role_id") == Role.ADMINISTRATEUR and user.get("is_active", True):
        count = await count_active_admins()
        if count <= 1:
            raise HTTPException(
                status_code=409,
                detail="Impossible de supprimer le dernier administrateur actif",
            )
    await es.delete(index=IDX, id=user_id, refresh="wait_for")


async def set_user_active(user_id: str, is_active: bool) -> Dict[str, Any]:
    return await update_user(user_id, {"is_active": is_active})
