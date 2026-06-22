"""
router.py — Endpoints d'authentification
Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-01, RF-SEC-03
"""

from fastapi import APIRouter, Request, Depends

from app.api.v1.auth.schemas import LoginRequest, TokenWithProfile, UserProfile
from app.api.v1.auth.service import authenticate_user, create_user_token, write_audit_log
from app.core.security import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentification"])


@router.post(
    "/login",
    response_model=TokenWithProfile,
    summary="Connexion utilisateur",
    description="Authentifie l'utilisateur et retourne un token JWT. Public.",
)
async def login(credentials: LoginRequest, request: Request):
    user = await authenticate_user(credentials.username, credentials.password)
    token_data = await create_user_token(user)

    # Audit log : connexion réussie (RF-SEC-03)
    await write_audit_log(
        user_id=user["id"],
        action="connexion",
        ip_address=request.client.host if request.client else None,
        details={"username": user["username"]},
    )

    return token_data


@router.get(
    "/me",
    response_model=UserProfile,
    summary="Profil utilisateur courant",
    description="Retourne le profil de l'utilisateur connecté. JWT requis.",
)
async def get_me(current_user: dict = Depends(get_current_user)):
    return UserProfile(
        user_id=current_user["sub"],
        username=current_user["username"],
        role=current_user["role"],
        org_scope=current_user.get("org_scope"),
        is_active=True,
    )


@router.post(
    "/logout",
    summary="Déconnexion",
    description="Enregistre la déconnexion dans le journal d'audit.",
)
async def logout(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    # Audit log : déconnexion (RF-SEC-03)
    await write_audit_log(
        user_id=current_user["sub"],
        action="deconnexion",
        ip_address=request.client.host if request.client else None,
    )
    return {"message": "Déconnexion enregistrée. Supprimez le token côté client."}
