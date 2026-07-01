from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from app.auth.models import LoginRequest, TOTPChallenge, TokenResponse
from app.auth import services

# Préfixe /auth et regroupement sous le tag "Authentication" dans la doc OpenAPI.
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest) -> TokenResponse:
    # Vérifie les identifiants (comptes de démo, voir services.DEMO_USERS).
    user = services.validate_credentials(payload.username, payload.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if user.get("mfa_enabled"):
        # Le mot de passe est correct mais la double authentification est activée :
        # on ne délivre pas encore de token d'accès, seulement un jeton MFA temporaire.
        return TokenResponse(
            mfa_required=True,
            mfa_token=services.create_mfa_challenge(user["id"]),
            user={
                "user_id": user["id"],
                "username": user["username"],
                "role": user.get("role"),
                "org_scope": user.get("org_scope"),
                "is_active": True,
                "mfa_enabled": True,
            },
        )

    # Pas de MFA requis : on délivre directement les tokens d'accès/rafraîchissement.
    token_payload = services.issue_tokens(user)
    return TokenResponse(**token_payload)


@router.post("/mfa/verify", response_model=TokenResponse)
async def verify_mfa(challenge: TOTPChallenge) -> TokenResponse:
    # Valide le code TOTP saisi par l'utilisateur suite à un /login avec mfa_required=True.
    if not services.verify_totp(challenge.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP")
    # NOTE : renvoie un jeton MFA (et non un vrai access token) — cohérent avec le
    # caractère "démo" simplifié de ce module.
    return TokenResponse(access_token=services.create_mfa_challenge("demo"), token_type="bearer")
