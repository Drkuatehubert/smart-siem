"""
schemas.py — Schémas Pydantic pour l'authentification (durcis)

Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-01, NFR-SEC-03

Modèles exposés :
  * LoginRequest, LoginResponseMfa
  * TokenResponse, TokenWithProfile
  * RefreshRequest, RefreshResponse
  * MfaSetupResponse, MfaVerifyRequest
  * PasswordChangeRequest, PasswordResetRequest, PasswordResetConfirm
  * UserProfile
"""

from __future__ import annotations

import re
from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ─────────────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    """Identifiants soumis par le client. Validation de format seule ;
    l'authentification réelle (lockout, audit, etc.) est dans `service.authenticate_user`.
    """
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(..., min_length=1, max_length=4096)  # borne haute anti-DoS

    class Config:
        json_schema_extra = {
            "example": {"username": "analyste01", "password": "MonMotDePasse123!"},
        }


class UserProfile(BaseModel):
    """Profil public de l'utilisateur (jamais de hash, jamais d'email non validé)."""
    user_id: str
    username: str
    email: Optional[EmailStr] = None
    role: str
    org_scope: Optional[str] = None
    is_active: bool
    mfa_enabled: bool = False


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int  # secondes


class TokenWithProfile(BaseModel):
    """Réponse de login. `access_token` peut être None si MFA requis (renvoyé en `mfa_token`)."""
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None
    user: UserProfile


class LoginResponseMfa(BaseModel):
    """Sous-réponse envoyée quand `MFA_REQUIRED=True`."""
    mfa_required: bool = True
    mfa_token: str
    token_type: str = "mfa"
    user: UserProfile


# ─────────────────────────────────────────────────────────────────────
# Refresh
# ─────────────────────────────────────────────────────────────────────

class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=20)


class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# ─────────────────────────────────────────────────────────────────────
# MFA
# ─────────────────────────────────────────────────────────────────────

class MfaSetupResponse(BaseModel):
    """Réponse de /auth/mfa/setup. Contient le secret (à encoder côté client)
    et l'URI otpauth:// pour QR code.
    """
    secret: str
    otpauth_uri: str


class MfaVerifyRequest(BaseModel):
    mfa_token: str = Field(..., min_length=20)
    code: str = Field(..., min_length=6, max_length=8, pattern=r"^\d+$")


# ─────────────────────────────────────────────────────────────────────
# Mot de passe
# ─────────────────────────────────────────────────────────────────────

_PASSWORD_POLICY_HINT = (
    "12 caractères minimum, avec majuscule, minuscule, chiffre et symbole."
)


def _validate_password_strength(value: str) -> str:
    """Vérifie la politique (PASSWORD_*). Lève ValueError si non conforme."""
    from app.config import settings
    if len(value) < settings.PASSWORD_MIN_LENGTH:
        raise ValueError(f"Mot de passe trop court (min {settings.PASSWORD_MIN_LENGTH}).")
    if len(value) > settings.PASSWORD_MAX_LENGTH:
        raise ValueError(f"Mot de passe trop long (max {settings.PASSWORD_MAX_LENGTH}).")
    if settings.PASSWORD_REQUIRE_UPPER and not re.search(r"[A-Z]", value):
        raise ValueError("Au moins une majuscule requise.")
    if settings.PASSWORD_REQUIRE_LOWER and not re.search(r"[a-z]", value):
        raise ValueError("Au moins une minuscule requise.")
    if settings.PASSWORD_REQUIRE_DIGIT and not re.search(r"\d", value):
        raise ValueError("Au moins un chiffre requis.")
    if settings.PASSWORD_REQUIRE_SYMBOL and not re.search(r"[^\w\s]", value):
        raise ValueError("Au moins un symbole requis.")
    return value


class PasswordChangeRequest(BaseModel):
    old_password: str = Field(..., min_length=1, max_length=4096)
    new_password: str = Field(..., min_length=1, max_length=4096)

    @field_validator("new_password")
    @classmethod
    def _check_strength(cls, v: str) -> str:
        return _validate_password_strength(v)


class PasswordResetRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9._-]+$")


class PasswordResetConfirm(BaseModel):
    reset_token: str = Field(..., min_length=20)
    new_password: str = Field(..., min_length=1, max_length=4096)

    @field_validator("new_password")
    @classmethod
    def _check_strength(cls, v: str) -> str:
        return _validate_password_strength(v)
