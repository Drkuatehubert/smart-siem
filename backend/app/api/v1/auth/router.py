"""
router.py â€” Endpoints d'authentification (durcis)

Responsable : Chef de Projet & SÃ©curitÃ©
Exigences : RF-SEC-01, RF-SEC-03 (audit), NFR-SEC-04 (lockout, MFA, password reset)

Endpoints :
  POST /auth/login           â€” login (rate-limited)
  GET  /auth/me              â€” profil courant (JWT, is_active revÃ©rifiÃ© en ES)
  POST /auth/logout          â€” rÃ©voque le jti (logout serveur-side)
  POST /auth/refresh         â€” rotate access token via refresh token
  POST /auth/mfa/setup       â€” gÃ©nÃ¨re le secret TOTP et l'URI otpauth://
  POST /auth/mfa/verify      â€” complÃ¨te un login MFA
  POST /auth/password/change â€” change le mot de passe (politique + historique)
  POST /auth/password/reset-request   â€” envoie un email avec token (Redis 30 min)
  POST /auth/password/reset-confirm   â€” consomme le token et applique le nouveau mdp
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Optional

import pyotp  # type: ignore[import-untyped]
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.config import settings
from app.core.security import (
    decode_refresh_token,
    require_validated_user,
    revoke_jti,
)
from app.core.elasticsearch import get_es_client
from app.core.redis_client import get_redis_client
from app.api.v1.auth.schemas import (
    LoginRequest,
    MfaSetupResponse,
    MfaVerifyRequest,
    PasswordChangeRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
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
from app.core.rate_limit import limiter  # noqa: F401  (slowapi decorator utilisÃ© ci-dessous)

router = APIRouter(prefix="/auth", tags=["Authentification"])


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Helpers
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _request_meta(request: Request) -> dict:
    return {
        "ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "request_id": getattr(request.state, "request_id", None),
        "method": request.method,
        "path": request.url.path,
    }


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Login
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/login",
    response_model=TokenWithProfile,
    summary="Connexion utilisateur",
    description="Authentifie l'utilisateur et retourne un token JWT (ou un mfa_token si MFA).",
)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def login(request: Request, credentials: LoginRequest):
    meta = _request_meta(request)
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


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# /me â€” profil courant
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.get(
    "/me",
    response_model=UserProfile,
    summary="Profil utilisateur courant",
    description="Retourne le profil de l'utilisateur connectÃ© (vÃ©rifiÃ© en ES).",
)
async def get_me(
    request: Request,
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


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Logout (rÃ©voque le jti cÃ´tÃ© serveur)
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/logout",
    summary="DÃ©connexion",
    description="RÃ©voque le token JWT courant et journalise la dÃ©connexion.",
)
async def logout(
    request: Request,
    current_user: dict = Depends(require_validated_user),
):
    meta = _request_meta(request)
    jti = current_user.get("jti")
    exp = current_user.get("exp")
    if jti and exp:
        try:
            revoke_jti(jti, datetime.fromtimestamp(exp, tz=timezone.utc))
        except Exception:
            pass
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
    return {"message": "DÃ©connexion enregistrÃ©e. Token rÃ©voquÃ©."}


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Refresh
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/refresh",
    response_model=RefreshResponse,
    summary="Renouvelle un access token Ã  partir d'un refresh token",
)
@limiter.limit("20/minute")
async def refresh(request: Request, body: RefreshRequest):
    try:
        payload = decode_refresh_token(body.refresh_token)
    except HTTPException:
        raise
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token invalide")
    new_tokens = await refresh_user_token(user_id)
    return RefreshResponse(**new_tokens)


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# MFA setup & verify
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/mfa/setup",
    response_model=MfaSetupResponse,
    summary="GÃ©nÃ¨re un secret TOTP pour MFA",
    description="Retourne un secret + URI otpauth:// Ã  scanner dans Google Authenticator.",
)
async def mfa_setup(
    request: Request,
    current_user: dict = Depends(require_validated_user),
):
    secret = pyotp.random_base32()
    es = get_es_client()
    await es.update(
        index="idx-users",
        id=current_user["sub"],
        doc={"mfa_pending_secret": secret, "mfa_enabled": False},
    )
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
    summary="VÃ©rifie le code TOTP et complÃ¨te le login MFA",
)
@limiter.limit("10/minute")
async def mfa_verify(request: Request, body: MfaVerifyRequest):
    from app.core.security import decode_token  # local
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
    # Confirme le MFA
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
    return await create_user_token({**src, "id": user_id})


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Password change / reset
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@router.post(
    "/password/change",
    summary="Changement de mot de passe (authentifiÃ©)",
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
        await write_audit_log(
            user_id=current_user["sub"],
            action="changement_mdp_echec",
            ip_address=request.client.host if request.client else None,
            request_id=getattr(request.state, "request_id", None),
            status="failure",
        )
        raise HTTPException(status_code=401, detail="Mot de passe actuel incorrect")

    # Politique + historique
    new_hash = hash_password(body.new_password)
    history: list = src.get("password_history", [])
    for h in history[-settings.PASSWORD_HISTORY_SIZE:]:
        if verify_password(body.new_password, h):
            raise HTTPException(status_code=400, detail="Mot de passe dÃ©jÃ  utilisÃ© rÃ©cemment")

    history.append(new_hash)
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
    return {"message": "Mot de passe mis Ã  jour."}


@router.post(
    "/password/reset-request",
    summary="Demande de rÃ©initialisation de mot de passe (public, sans fuite d'info)",
)
@limiter.limit("5/minute")
async def password_reset_request(request: Request, body: PasswordResetRequest):
    """
    RÃ©ponse constante (200 dans tous les cas) pour Ã©viter l'Ã©numÃ©ration.
    Le mail n'est envoyÃ© que si l'utilisateur existe.
    """
    meta = _request_meta(request)
    es = get_es_client()
    try:
        res = await es.search(
            index="idx-users",
            query={"term": {"username": body.username.lower()}},
            size=1,
        )
        hits = res["hits"]["hits"]
    except Exception:
        hits = []

    if hits:
        token = secrets.token_urlsafe(32)
        r = get_redis_client()
        await r.set(f"pwd_reset:{token}", hits[0]["_id"], ex=1800)  # 30 min
        # En prod, brancher SMTP ici. En dev, on log seulement.
        import logging
        logging.getLogger("auth").info(
            "[DEV] reset token=%s user_id=%s", token, hits[0]["_id"],
        )
        await write_audit_log(
            user_id=hits[0]["_id"],
            action="reset_mdp_demande",
            ip_address=meta["ip"],
            user_agent=meta["user_agent"],
            request_id=meta["request_id"],
        )

    return {"message": "Si le compte existe, un email a Ã©tÃ© envoyÃ©."}


@router.post(
    "/password/reset-confirm",
    summary="Confirme un reset de mot de passe (public, token en Redis)",
)
@limiter.limit("5/minute")
async def password_reset_confirm(request: Request, body: PasswordResetConfirm):
    from app.core.security import hash_password
    r = get_redis_client()
    user_id = await r.get(f"pwd_reset:{body.reset_token}")
    if not user_id:
        raise HTTPException(status_code=400, detail="Token invalide ou expirÃ©")
    new_hash = hash_password(body.new_password)
    es = get_es_client()
    doc = await es.get(index="idx-users", id=user_id)
    history = (doc["_source"].get("password_history") or [])
    history.append(new_hash)
    history = history[-settings.PASSWORD_HISTORY_SIZE:]
    await es.update(
        index="idx-users",
        id=user_id,
        doc={
            "password_hash": new_hash,
            "password_history": history,
            "must_reset_password": False,
            "locked_until": None,
        },
    )
    await r.delete(f"pwd_reset:{body.reset_token}")
    await write_audit_log(
        user_id=user_id,
        action="reset_mdp_confirme",
        ip_address=request.client.host if request.client else None,
        request_id=getattr(request.state, "request_id", None),
    )
    return {"message": "Mot de passe rÃ©initialisÃ©."}
