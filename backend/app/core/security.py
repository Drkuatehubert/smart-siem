"""
security.py — Gestion JWT et hachage des mots de passe
Responsable : Chef de Projet & Sécurité
Exigences couvertes : RF-SEC-01, NFR-SEC-02, NFR-SEC-03
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.config import settings

# OAuth2 scheme — token transmis via Authorization: Bearer <token>
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# ─────────────────────────────────────────────
# Hachage des mots de passe (bcrypt)
# ─────────────────────────────────────────────

def hash_password(plain_password: str) -> str:
    """Hache un mot de passe en clair avec bcrypt (salt auto-généré)."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifie qu'un mot de passe correspond au hash stocké."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8")
    )


# ─────────────────────────────────────────────
# Gestion des tokens JWT
# ─────────────────────────────────────────────

def create_access_token(
    user_id: str,
    username: str,
    role: str,
    org_scope: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Génère un token JWT signé.
    Payload : user_id, username, role, org_scope, exp.
    """
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_EXPIRY_MINUTES)
    )
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "org_scope": org_scope,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.API_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Décode et valide un token JWT.
    Lève HTTPException 401 si invalide ou expiré.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalide ou expiré",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.API_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception


# ─────────────────────────────────────────────
# Dépendance FastAPI : utilisateur courant
# ─────────────────────────────────────────────

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Dépendance injectable : extrait l'utilisateur depuis le JWT.
    Usage : user = Depends(get_current_user)
    """
    return decode_access_token(token)
