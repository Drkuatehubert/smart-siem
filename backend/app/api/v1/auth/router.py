"""
router.py — Endpoints d'authentification (durcis)

Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-01, RF-SEC-03 (audit), NFR-SEC-04 (lockout, MFA, password reset)

Endpoints :
  POST /auth/login           — login
  GET  /auth/me              — profil courant (JWT, is_active revérifié en ES)
  POST /auth/logout          — journalise la déconnexion
  POST /auth/refresh         — rotate access token via refresh token
  POST /auth/mfa/setup       — génère le secret TOTP et l'URI otpauth://
  POST /auth/mfa/verify      — complète un login MFA
  POST /auth/password/change — change le mot de passe (politique + historique)
"""

from __future__ import annotations

from typing import Optional

import pyotp  # type: ignore[import-untyped]
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.config import settings
from app.core.security import (
    decode_refresh_token,
    require_validated_user,
)
from app.core.elasticsearch import get_es_client
from app.api.v1.auth.schemas import (
    LoginRequest,
    MfaSetupResponse,
    MfaVerifyRequest,
    PasswordChangeRequest,
    RefreshRequest,
    RefreshResponse,
    TokenWithProfile,
    UserProfile,
)
from app.api.v1.auth.service import (
    authenticate_user,
    create_user_token,
    refresh_user_token,
    write_audit_log,
)

router = APIRouter(prefix="/auth", tags=["Authentification"])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _request_meta(request: Request) -> dict:
    # Regroupe les informations de contexte de la requête HTTP couramment utilisées
    # pour l'audit (IP, user-agent, request_id, méthode, chemin), évite de les
    # récupérer manuellement dans chaque endpoint.
    return {
        "ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "request_id": getattr(request.state, "request_id", None),
        "method": request.method,
        "path": request.url.path,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/login",
    response_model=TokenWithProfile,
    summary="Connexion utilisateur",
    description="Authentifie l'utilisateur et retourne un token JWT (ou un mfa_token si MFA).",
)
async def login(request: Request, credentials: LoginRequest):
    meta = _request_meta(request)
    # Toute la logique de vérification (mot de passe, timing constant)
    # est déléguée à authenticate_user, qui lève une HTTPException en cas d'échec.
    user = await authenticate_user(
        credentials.username,
        credentials.password,
        ip=meta["ip"],
        user_agent=meta["user_agent"],
        request_id=meta["request_id"],
    )
    token_data = await create_user_token(user)
    await write_audit_log(
        user_id=user["id"],
        action="connexion",
        ip_address=meta["ip"],
        user_agent=meta["user_agent"],
        request_id=meta["request_id"],
        http_method=meta["method"],
        http_path=meta["path"],
        status="success",
        details={"username": user["username"]},
    )
    return token_data


# ─────────────────────────────────────────────────────────────────────────────
# /me — profil courant
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/me",
    response_model=UserProfile,
    summary="Profil utilisateur courant",
    description="Retourne le profil de l'utilisateur connecté (vérifié en ES).",
)
async def get_me(
    request: Request,
    # Depends(require_validated_user) : FastAPI exécute cette dépendance avant la fonction ;
    # si le JWT est invalide/expiré/révoqué ou le compte désactivé, elle lève 401 automatiquement.
    current_user: dict = Depends(require_validated_user),
):
    es = get_es_client()
    try:
        doc = await es.get(index="idx-users", id=current_user["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    src = doc["_source"]
    return UserProfile(
        user_id=current_user["sub"],
        username=src["username"],
        email=src.get("email"),
        role=src["role_id"],
        org_scope=src.get("org_scope"),
        is_active=bool(src.get("is_active", False)),
        mfa_enabled=bool(src.get("mfa_enabled", False)),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Logout
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/logout",
    summary="Déconnexion",
    description="Journalise la déconnexion.",
)
async def logout(
    request: Request,
    current_user: dict = Depends(require_validated_user),
):
    # Un JWT classique reste valide jusqu'à son expiration même après "déconnexion" côté client
    # (il suffit de le garder) : aucune révocation côté serveur n'est appliquée ici.
    meta = _request_meta(request)
    await write_audit_log(
        user_id=current_user["sub"],
        action="deconnexion",
        ip_address=meta["ip"],
        user_agent=meta["user_agent"],
        request_id=meta["request_id"],
        http_method=meta["method"],
        http_path=meta["path"],
        status="success",
    )
    return {"message": "Déconnexion enregistrée."}


# ─────────────────────────────────────────────────────────────────────────────
# Refresh
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/refresh",
    response_model=RefreshResponse,
    summary="Renouvelle un access token à partir d'un refresh token",
)
async def refresh(request: Request, body: RefreshRequest):
    # decode_refresh_token vérifie signature/expiration/type="refresh" ;
    # toute anomalie lève directement une HTTPException 401 qu'on laisse remonter.
    try:
        payload = decode_refresh_token(body.refresh_token)
    except HTTPException:
        raise
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token invalide")
    new_tokens = await refresh_user_token(user_id)
    return RefreshResponse(**new_tokens)


# ─────────────────────────────────────────────────────────────────────────────
# MFA setup & verify
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/mfa/setup",
    response_model=MfaSetupResponse,
    summary="Génère un secret TOTP pour MFA",
    description="Retourne un secret + URI otpauth:// à scanner dans Google Authenticator.",
)
async def mfa_setup(
    request: Request,
    current_user: dict = Depends(require_validated_user),
):
    # Génère un secret aléatoire propre à cet utilisateur (jamais partagé/codé en dur,
    # contrairement au module de démo backend/app/auth/).
    secret = pyotp.random_base32()
    es = get_es_client()
    # Le secret est stocké en "pending" : il ne devient actif (mfa_enabled=True) qu'après
    # vérification réussie d'un premier code via /mfa/verify (évite qu'un setup abandonné
    # en cours de route ne verrouille silencieusement le compte).
    await es.update(
        index="idx-users",
        id=current_user["sub"],
        doc={"mfa_pending_secret": secret, "mfa_enabled": False},
    )
    # L'URI "otpauth://" encode le secret et les paramètres TOTP dans un format standard
    # que les applications d'authentification savent lire (généralement via un QR code).
    uri = pyotp.TOTP(secret, digits=settings.MFA_TOTP_DIGITS, interval=settings.MFA_TOTP_PERIOD).provisioning_uri(
        name=current_user["username"],
        issuer_name=settings.MFA_ISSUER,
    )
    await write_audit_log(
        user_id=current_user["sub"],
        action="mfa_setup_initie",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        request_id=getattr(request.state, "request_id", None),
        http_method=request.method,
        http_path=request.url.path,
    )
    return MfaSetupResponse(secret=secret, otpauth_uri=uri)


@router.post(
    "/mfa/verify",
    response_model=TokenWithProfile,
    summary="Vérifie le code TOTP et complète le login MFA",
)
async def mfa_verify(request: Request, body: MfaVerifyRequest):
    from app.core.security import decode_token  # import local, évite un cycle au chargement du module
    # Le mfa_token a été émis par /login (via create_user_token) quand mfa_enabled=True :
    # on vérifie ici qu'il est valide et toujours de type "mfa" avant de continuer.
    try:
        payload = decode_token(body.mfa_token, expected_type="mfa")
    except HTTPException:
        raise
    user_id = payload["sub"]
    es = get_es_client()
    doc = await es.get(index="idx-users", id=user_id)
    src = doc["_source"]
    pending = src.get("mfa_pending_secret")
    if not pending:
        # Cas : mfa_verify appelé sans setup préalable en cours (aucun secret en attente).
        raise HTTPException(status_code=400, detail="Aucun setup MFA en cours")
    totp = pyotp.TOTP(pending, digits=settings.MFA_TOTP_DIGITS, interval=settings.MFA_TOTP_PERIOD)
    if not totp.verify(body.code, valid_window=1):
        await write_audit_log(
            user_id=user_id,
            action="mfa_code_invalide",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            request_id=getattr(request.state, "request_id", None),
            status="failure",
        )
        raise HTTPException(status_code=401, detail="Code MFA invalide")
    # Le code est correct : on active définitivement le MFA et on efface le secret "pending".
    await es.update(
        index="idx-users",
        id=user_id,
        doc={"mfa_enabled": True, "mfa_pending_secret": None},
    )
    await write_audit_log(
        user_id=user_id,
        action="mfa_active",
        ip_address=request.client.host if request.client else None,
        request_id=getattr(request.state, "request_id", None),
        status="success",
    )
    # Émet enfin les vrais tokens d'accès (le login est maintenant complet).
    return await create_user_token({**src, "id": user_id})


# ─────────────────────────────────────────────────────────────────────────────
# Password change
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/password/change",
    summary="Changement de mot de passe (authentifié)",
)
async def password_change(
    request: Request,
    body: PasswordChangeRequest,
    current_user: dict = Depends(require_validated_user),
):
    from app.core.security import verify_password, hash_password
    es = get_es_client()
    doc = await es.get(index="idx-users", id=current_user["sub"])
    src = doc["_source"]
    if not verify_password(body.old_password, src["password_hash"]):
        # On exige de reconfirmer le mot de passe actuel avant de le changer, pour éviter
        # qu'une session volée (mais token valide) ne permette de tout changer sans rien connaître.
        await write_audit_log(
            user_id=current_user["sub"],
            action="changement_mdp_echec",
            ip_address=request.client.host if request.client else None,
            request_id=getattr(request.state, "request_id", None),
            status="failure",
        )
        raise HTTPException(status_code=401, detail="Mot de passe actuel incorrect")

    # Politique + historique : le nouveau mot de passe est validé par le schéma
    # (PasswordChangeRequest) et on vérifie ici qu'il ne reprend pas un mot de passe récent.
    new_hash = hash_password(body.new_password)
    history: list = src.get("password_history", [])
    for h in history[-settings.PASSWORD_HISTORY_SIZE:]:
        if verify_password(body.new_password, h):
            raise HTTPException(status_code=400, detail="Mot de passe déjà utilisé récemment")

    history.append(new_hash)
    # On ne garde que les N derniers hash (PASSWORD_HISTORY_SIZE), pour ne pas faire
    # grossir indéfiniment le document utilisateur.
    history = history[-settings.PASSWORD_HISTORY_SIZE:]
    await es.update(
        index="idx-users",
        id=current_user["sub"],
        doc={
            "password_hash": new_hash,
            "password_history": history,
            "must_reset_password": False,
        },
    )
    await write_audit_log(
        user_id=current_user["sub"],
        action="changement_mdp",
        ip_address=request.client.host if request.client else None,
        request_id=getattr(request.state, "request_id", None),
        status="success",
    )
    return {"message": "Mot de passe mis à jour."}
