"""router.py – Endpoints de gestion des utilisateurs.

Endpoints (tous sous /api/v1/users) :
  GET    /                     – liste paginée (admin/auditeur)
  GET    /{user_id}            – détail (admin/auditeur)
  POST   /                     – création (admin)
  PATCH  /{user_id}            – modification partielle (admin)
  DELETE /{user_id}            – suppression (admin)
  POST   /{user_id}/disable    – désactivation (admin)
  POST   /{user_id}/enable     – réactivation (admin)
  PATCH  /{user_id}/role       – changement de rôle (admin)
  POST   /{user_id}/reset-password – reset MDP temporaire (admin)
  GET    /{user_id}/activity   – profil de risque / activité (admin/auditeur)
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.rbac import require_admin, require_auditor
from app.api.v1.auth.service import write_audit_log
from app.api.v1.users.schemas import (
    DeleteUserResponse,
    SetActiveRequest,
    UserCreate,
    UserListResponse,
    UserRoleUpdate,
    UserUpdate,
)
from app.api.v1.users.service import (
    create_user,
    delete_user,
    get_user_activity,
    get_user_by_id,
    list_users,
    reset_password,
    set_user_active,
    update_role,
    update_user,
)

router = APIRouter(prefix="/users", tags=["Utilisateurs"])


def _meta(request: Request) -> dict:
    return {
        "ip": request.client.host if request.client else None,
        "ua": request.headers.get("user-agent"),
        "rid": getattr(request.state, "request_id", None),
        "method": request.method,
        "path": request.url.path,
    }


@router.get("", response_model=UserListResponse)
async def get_users(
    page: int = 1,
    size: int = 50,
    current_user: dict = Depends(require_auditor),
):
    return await list_users(page=page, size=size)


@router.get("/{user_id}/activity")
async def get_activity(
    user_id: str,
    current_user: dict = Depends(require_auditor),
):
    return await get_user_activity(user_id)


@router.get("/{user_id}")
async def get_user(
    user_id: str,
    current_user: dict = Depends(require_auditor),
):
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    return user


@router.post("", status_code=201)
async def create(
    request: Request,
    body: UserCreate,
    current_user: dict = Depends(require_admin),
):
    m = _meta(request)
    result = await create_user(body.model_dump())
    await write_audit_log(
        user_id=current_user["sub"],
        action="user_created",
        ip_address=m["ip"],
        user_agent=m["ua"],
        request_id=m["rid"],
        http_method=m["method"],
        http_path=m["path"],
        target_entity="utilisateur",
        target_id=result["id"],
        details={"role": result.get("role"), "org_scope": result.get("org_scope")},
    )
    return result


@router.patch("/{user_id}/role")
async def change_role(
    user_id: str,
    request: Request,
    body: UserRoleUpdate,
    current_user: dict = Depends(require_admin),
):
    m = _meta(request)
    result = await update_role(user_id, body.role)
    await write_audit_log(
        user_id=current_user["sub"],
        action="role_changed",
        ip_address=m["ip"],
        user_agent=m["ua"],
        request_id=m["rid"],
        http_method=m["method"],
        http_path=m["path"],
        target_entity="utilisateur",
        target_id=user_id,
        details={"new_role": body.role},
    )
    return result


@router.post("/{user_id}/reset-password")
async def do_reset_password(
    user_id: str,
    request: Request,
    current_user: dict = Depends(require_admin),
):
    m = _meta(request)
    result = await reset_password(user_id)
    await write_audit_log(
        user_id=current_user["sub"],
        action="password_changed",
        ip_address=m["ip"],
        user_agent=m["ua"],
        request_id=m["rid"],
        http_method=m["method"],
        http_path=m["path"],
        target_entity="utilisateur",
        target_id=user_id,
    )
    return result


@router.patch("/{user_id}")
async def patch_user(
    user_id: str,
    request: Request,
    body: UserUpdate,
    current_user: dict = Depends(require_admin),
):
    m = _meta(request)
    result = await update_user(user_id, body.model_dump(exclude_unset=True))
    if not result:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    await write_audit_log(
        user_id=current_user["sub"],
        action="role_changed",
        ip_address=m["ip"],
        user_agent=m["ua"],
        request_id=m["rid"],
        http_method=m["method"],
        http_path=m["path"],
        target_entity="utilisateur",
        target_id=user_id,
        details=body.model_dump(exclude_unset=True),
    )
    return result


@router.delete("/{user_id}", response_model=DeleteUserResponse)
async def delete(
    user_id: str,
    request: Request,
    current_user: dict = Depends(require_admin),
):
    m = _meta(request)
    await delete_user(user_id)
    await write_audit_log(
        user_id=current_user["sub"],
        action="user_deleted",
        ip_address=m["ip"],
        user_agent=m["ua"],
        request_id=m["rid"],
        http_method=m["method"],
        http_path=m["path"],
        target_entity="utilisateur",
        target_id=user_id,
    )
    return DeleteUserResponse(id=user_id, deleted=True)


@router.post("/{user_id}/disable")
async def disable(
    user_id: str,
    request: Request,
    current_user: dict = Depends(require_admin),
):
    m = _meta(request)
    result = await set_user_active(user_id, False)
    if not result:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    await write_audit_log(
        user_id=current_user["sub"],
        action="role_changed",
        ip_address=m["ip"],
        user_agent=m["ua"],
        request_id=m["rid"],
        target_entity="utilisateur",
        target_id=user_id,
        details={"is_active": False},
    )
    return result


@router.post("/{user_id}/enable")
async def enable(
    user_id: str,
    request: Request,
    body: SetActiveRequest,
    current_user: dict = Depends(require_admin),
):
    m = _meta(request)
    result = await set_user_active(user_id, body.is_active)
    if not result:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    await write_audit_log(
        user_id=current_user["sub"],
        action="role_changed",
        ip_address=m["ip"],
        user_agent=m["ua"],
        request_id=m["rid"],
        target_entity="utilisateur",
        target_id=user_id,
        details={"is_active": body.is_active},
    )
    return result
