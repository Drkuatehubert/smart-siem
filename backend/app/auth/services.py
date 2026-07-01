from __future__ import annotations

import secrets
from typing import Any

import pyotp  # génération/vérification de codes TOTP (mots de passe à usage unique basés sur le temps)

from app.core.security import create_access_token, create_mfa_token, create_refresh_token


# ATTENTION : ceci est un module de DÉMONSTRATION. Les utilisateurs et mots de passe sont
# codés en dur en clair (pas de hachage bcrypt, pas de lecture en base Elasticsearch).
# Le module d'authentification réellement utilisé par le frontend en production est
# backend/app/api/v1/auth/ (qui, lui, vérifie les mots de passe hachés stockés dans ES).
DEMO_USERS = {
    "admin": {
        "id": "demo-admin",
        "username": "admin",
        "password": "admin",
        "role": "administrateur",
        "org_scope": "default",
        "mfa_enabled": False,
    },
    "analyste": {
        "id": "demo-analyste",
        "username": "analyste",
        "password": "analyste",
        "role": "analyste",
        "org_scope": "default",
        "mfa_enabled": False,
    },
}


def validate_credentials(username: str, password: str) -> dict[str, Any] | None:
    # Comparaison directe des mots de passe en clair : acceptable uniquement parce
    # qu'il s'agit de comptes de démonstration fixes, jamais pour de vrais comptes utilisateurs.
    user = DEMO_USERS.get(username)
    if user and user["password"] == password:
        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "org_scope": user["org_scope"],
            "mfa_enabled": user["mfa_enabled"],
        }
    return None


def issue_jwt(user: dict[str, Any]) -> str:
    # Émet uniquement un access token (pas de refresh token) : utilisé par d'anciens appelants.
    return create_access_token(
        user_id=user["id"],
        username=user["username"],
        role=user.get("role", "lecteur"),
        org_scope=user.get("org_scope"),
    )


def issue_tokens(user: dict[str, Any]) -> dict[str, Any]:
    # Émet la paire complète access + refresh token, ainsi que les informations
    # utilisateur renvoyées telles quelles au frontend après connexion.
    access_token = create_access_token(
        user_id=user["id"],
        username=user["username"],
        role=user.get("role", "lecteur"),
        org_scope=user.get("org_scope"),
    )
    refresh_token = create_refresh_token(user["id"])
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": 15 * 60,  # durée de vie de l'access token en secondes (doit rester cohérent avec JWT_EXPIRY_MINUTES)
        "user": {
            "user_id": user["id"],
            "username": user["username"],
            "role": user.get("role", "lecteur"),
            "org_scope": user.get("org_scope"),
            "is_active": True,
            "mfa_enabled": user.get("mfa_enabled", False),
        },
    }


def verify_totp(code: str, secret: str | None = None) -> bool:
    # Vérifie un code TOTP à 6 chiffres par rapport à un secret partagé.
    # NOTE démo : secret par défaut codé en dur si aucun n'est fourni (à ne jamais faire
    # avec de vrais utilisateurs, chacun doit avoir son propre secret MFA généré et stocké).
    if not secret:
        secret = "JBSWY3DPEHPK3PXP"
    totp = pyotp.TOTP(secret)
    # valid_window=1 tolère un décalage d'une période (30s) avant/après, pour absorber
    # les petites différences d'horloge entre le serveur et le téléphone de l'utilisateur.
    return totp.verify(code, valid_window=1)


def create_mfa_challenge(user_id: str) -> str:
    # Émet le jeton temporaire (5 min) que le client doit renvoyer avec son code TOTP.
    return create_mfa_token(user_id)
