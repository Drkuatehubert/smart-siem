"""
router.py — Endpoints de gestion des utilisateurs (durcis)

Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-02, RF-SEC-04

Endpoints (tous sous /api/v1/users) :
  GET    /                  — liste paginée (admin/auditeur)
  GET    /{user_id}         — détail (admin/auditeur)
  POST   /                  — création (admin)
  PATCH  /{user_id}         — modification partielle (admin, last-admin guard)
  DELETE /{user_id}         — suppression (admin, last-admin guard)
  POST   /{user_id}/disable — désactivation (admin, SOAR-friendly)
  POST   /{user_id}/enable  — réactivation (admin)
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.rbac import require_admin, require_auditor
from app.api.v1.auth.service import write_audit_log
from app.api.v1.users.schemas import (
    DeleteUserResponse,
    SetActiveRequest,
    UserCreate,
    UserListResponse,
    UserUpdate,
)
from app.api.v1.users.service import (
    create_user,
    delete_user,
    get_user_by_id,
    list_users,
    set_user_active,
    update_user,
)

router = APIRouter(prefix="/users", tags=["Utilisateurs"])


def _meta(request: Request) -> dict:
    # Contexte de requête réutilisé pour chaque écriture d'audit ci-dessous.
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
    # require_auditor : accessible aux administrateurs ET aux auditeurs (lecture seule).
    current_user: dict = Depends(require_auditor),
):
    return await list_users(page=page, size=size)


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
    # require_admin : seul un administrateur peut créer un utilisateur.
    current_user: dict = Depends(require_admin),
):
    m = _meta(request)
    result = await create_user(body.model_dump())
    # Chaque action sensible (création/modification/suppression/activation d'un
    # utilisateur) est tracée dans le journal d'audit, avec qui l'a fait et sur quelle cible.
    await write_audit_log(
        user_id=current_user["sub"],
        action="creation_utilisateur",
        ip_address=m["ip"],
        user_agent=m["ua"],
        request_id=m["rid"],
        http_method=m["method"],
        http_path=m["path"],
        target_entity="utilisateur",
        target_id=result["id"],
        details={"role_id": result.get("role_id"), "org_scope": result.get("org_scope")},
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
    # exclude_unset=True : seuls les champs explicitement envoyés par le client
    # sont transmis à update_user (un champ omis reste inchangé en base).
    result = await update_user(user_id, body.model_dump(exclude_unset=True))
    if not result:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    await write_audit_log(
        user_id=current_user["sub"],
        action="modification_utilisateur",
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
        action="suppression_utilisateur",
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
    # Endpoint dédié (plutôt que de passer par PATCH) car réutilisé tel quel par
    # les playbooks SOAR pour désactiver automatiquement un compte compromis.
    m = _meta(request)
    result = await set_user_active(user_id, False)
    if not result:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    await write_audit_log(
        user_id=current_user["sub"],
        action="utilisateur_desactive",
        ip_address=m["ip"],
        user_agent=m["ua"],
        request_id=m["rid"],
        target_entity="utilisateur",
        target_id=user_id,
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
        # L'action journalisée reflète le sens réel de l'opération, même si le nom
        # de l'endpoint est toujours "/enable" (body.is_active peut valoir False).
        action="utilisateur_reactive" if body.is_active else "utilisateur_desactive",
        ip_address=m["ip"],
        user_agent=m["ua"],
        request_id=m["rid"],
        target_entity="utilisateur",
        target_id=user_id,
    )
    return result
