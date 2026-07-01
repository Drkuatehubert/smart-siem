from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    # Schéma du corps de requête attendu par POST /auth/login (ce module de démo).
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    # Réponse renvoyée après connexion. Selon le cas, soit les tokens sont présents
    # (connexion directe réussie), soit mfa_required=True et mfa_token est renseigné
    # (l'utilisateur doit encore fournir son code TOTP via /auth/mfa/verify).
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int | None = None
    mfa_required: bool = False
    mfa_token: str | None = None
    user: dict[str, Any] | None = None


class TOTPChallenge(BaseModel):
    # Corps de requête pour valider le code affiché par l'application d'authentification
    # (Google Authenticator, etc.) après une connexion nécessitant la double authentification.
    mfa_token: str
    code: str = Field(..., min_length=6, max_length=8)
