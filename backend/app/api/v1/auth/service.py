"""
service.py — Logique métier d'authentification
Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-01, RF-SEC-03 (audit log), NFR-SEC-02
"""

from datetime import timedelta
from typing import Optional

from fastapi import HTTPException, status

from app.config import settings
from app.core.security import verify_password, create_access_token
from app.core.elasticsearch import get_es_client


async def authenticate_user(username: str, password: str) -> dict:
    """
    Authentifie un utilisateur :
    1. Recherche dans idx-users
    2. Vérifie le hash bcrypt
    3. Vérifie que le compte est actif
    Retourne le document utilisateur si succès, lève 401 sinon.
    """
    es = get_es_client()

    # Recherche de l'utilisateur par username
    result = await es.search(
        index="idx-users",
        body={
            "query": {"term": {"username": username}},
            "size": 1
        }
    )

    hits = result["hits"]["hits"]
    if not hits:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = hits[0]["_source"]
    user["id"] = hits[0]["_id"]

    # Vérification compte actif
    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Compte désactivé. Contactez un administrateur.",
        )

    # Vérification du mot de passe
    if not verify_password(password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def create_user_token(user: dict) -> dict:
    """Génère le token JWT pour un utilisateur authentifié."""
    token = create_access_token(
        user_id=user["id"],
        username=user["username"],
        role=user["role_id"],
        org_scope=user.get("org_scope"),
        expires_delta=timedelta(minutes=settings.JWT_EXPIRY_MINUTES),
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.JWT_EXPIRY_MINUTES * 60,
        "user": {
            "user_id": user["id"],
            "username": user["username"],
            "email": user.get("email"),
            "role": user["role_id"],
            "org_scope": user.get("org_scope"),
            "is_active": user.get("is_active", True),
        }
    }


async def write_audit_log(
    user_id: str,
    action: str,
    ip_address: Optional[str] = None,
    target_entity: Optional[str] = None,
    target_id: Optional[str] = None,
    details: Optional[dict] = None,
) -> None:
    """
    Écrit une entrée dans le journal d'audit (idx-audit-log).
    Append-only : aucune modification ni suppression possible.
    Exigence RF-SEC-03.
    """
    from datetime import datetime, timezone
    es = get_es_client()

    audit_entry = {
        "user_id": user_id,
        "action": action,
        "ip_address": ip_address,
        "target_entity": target_entity,
        "target_id": target_id,
        "details": details or {},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    await es.index(index="idx-audit-log", document=audit_entry)
