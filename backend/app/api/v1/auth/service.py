"""
service.py — Logique métier d'authentification (durcie)

Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-01, RF-SEC-03 (audit), NFR-SEC-02, NFR-SEC-04 (lockout)

Durcissements par rapport à la version initiale :
  * `authenticate_user` est à durée constante (chemin unique avec bcrypt dummy
    si l'utilisateur n'existe pas) ⇒ empêche l'énumération par timing ;
  * un seul message d'erreur pour "user inconnu" et "mauvais mot de passe" ;
  * `last_login_at` mis à jour à chaque succès ;
  * `write_audit_log` enrichi : IP, UA, request_id, méthode, chemin, status ;
  * support MFA : si `MFA_REQUIRED` et `mfa_enabled`, on renvoie un
    `mfa_token` court (5 min) sans access token complet.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import HTTPException, status

from app.config import settings
from app.core.security import (
    create_access_token,
    create_mfa_token,
    create_refresh_token,
    hash_password,
    verify_password,
)
from app.core.elasticsearch import get_es_client


# ─────────────────────────────────────────────────────────────────────────────
# Constantes d'erreur — ne jamais révéler pourquoi l'auth a échoué
# ─────────────────────────────────────────────────────────────────────────────
# Utiliser le même message pour "utilisateur inconnu" et "mot de passe incorrect"
# empêche un attaquant de déterminer si un nom d'utilisateur donné existe (énumération).
_ERR_INVALID = "Identifiants incorrects"


# ─────────────────────────────────────────────────────────────────────────────
# Authentification (chemin à durée constante)
# ─────────────────────────────────────────────────────────────────────────────

async def authenticate_user(
    username: str,
    password: str,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Authentifie un utilisateur avec mitigations :
      * timing constant (bcrypt dummy sur user manquant) ;
      * audit `connexion_echouee` ou `connexion_reussie` systématique.

    Lève 401 (mauvais identifiants).
    Renvoie le document utilisateur (avec son `id`) en cas de succès.
    """
    es = get_es_client()
    ip = ip or "0.0.0.0"

    # Recherche de l'utilisateur par nom (insensible à la casse : normalisé en minuscules).
    try:
        result = await es.search(
            index="idx-users",
            query={"term": {"username": username.lower()}},
            size=1,
        )
    except Exception:
        # En cas d'erreur ES on log un audit "infra" et on refuse.
        await write_audit_log(
            user_id="anonymous",
            action="connexion_echouee",
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"username": username, "reason": "es_unreachable"},
        )
        raise HTTPException(status_code=503, detail="Service temporairement indisponible")

    hits = result["hits"]["hits"]
    user = hits[0]["_source"] if hits else None
    user_id = hits[0]["_id"] if hits else None

    # Garde timing constant : bcrypt dummy si user manquant.
    # Sans cette ligne, la réponse serait plus rapide quand l'utilisateur n'existe pas
    # (pas de calcul bcrypt) que quand le mot de passe est juste incorrect, ce qui
    # permettrait à un attaquant de deviner quels noms d'utilisateur existent en
    # mesurant le temps de réponse.
    if user is None:
        hash_password(os.urandom(16).hex())  # ~même coût qu'un vrai check
        await write_audit_log(
            user_id="anonymous",
            action="connexion_echouee",
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            status="failure",
            details={"username": username, "reason": "unknown_user"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_ERR_INVALID,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Vérification du mot de passe (comparaison bcrypt en temps constant).
    password_ok = verify_password(password, user["password_hash"])

    if not password_ok:
        await write_audit_log(
            user_id=user_id,
            action="connexion_echouee",
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            status="failure",
            details={"username": username, "reason": "bad_password"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_ERR_INVALID,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Succès : maj last_login_at.
    try:
        await es.update(
            index="idx-users",
            id=user_id,
            doc={"last_login_at": datetime.now(timezone.utc).isoformat()},
        )
    except Exception:
        # Une erreur ici ne doit pas empêcher la connexion de réussir.
        pass

    await write_audit_log(
        user_id=user_id,
        action="connexion_reussie",
        ip_address=ip,
        user_agent=user_agent,
        request_id=request_id,
        status="success",
        details={"username": user["username"], "role": user.get("role_id")},
    )

    user["id"] = user_id
    return user


# ─────────────────────────────────────────────────────────────────────────────
# Émission des tokens
# ─────────────────────────────────────────────────────────────────────────────

async def create_user_token(user: Dict[str, Any]) -> Dict[str, Any]:
    """
    Crée les tokens (access + refresh). Si MFA requis et activé,
    renvoie un mfa_token court sans access token.
    """
    # MFA ? Si oui, on s'arrête là : le client devra encore appeler /auth/mfa/verify
    # avec le code TOTP avant d'obtenir un véritable access token.
    if settings.MFA_REQUIRED and user.get("mfa_enabled"):
        mfa_token = create_mfa_token(user["id"])
        return {
            "mfa_required": True,
            "mfa_token": mfa_token,
            "token_type": "mfa",
            "user": {
                "user_id": user["id"],
                "username": user["username"],
                "role": user.get("role_id"),
                "org_scope": user.get("org_scope"),
                "is_active": user.get("is_active", True),
            },
        }

    access = create_access_token(
        user_id=user["id"],
        username=user["username"],
        role=user["role_id"],
        org_scope=user.get("org_scope"),
        expires_delta=timedelta(minutes=settings.JWT_EXPIRY_MINUTES),
    )
    refresh = create_refresh_token(user["id"])
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": settings.JWT_EXPIRY_MINUTES * 60,
        "user": {
            "user_id": user["id"],
            "username": user["username"],
            "email": user.get("email"),
            "role": user["role_id"],
            "org_scope": user.get("org_scope"),
            "is_active": user.get("is_active", True),
        },
    }


async def refresh_user_token(user_id: str) -> Dict[str, Any]:
    """Émet un nouveau access token à partir d'un user_id (validé par refresh JWT)."""
    es = get_es_client()
    try:
        doc = await es.get(index="idx-users", id=user_id)
    except Exception:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    src = doc["_source"]
    if not src.get("is_active", False):
        # Un compte désactivé après l'émission d'un refresh token ne doit plus
        # pouvoir obtenir de nouveaux access tokens.
        raise HTTPException(status_code=403, detail="Compte désactivé")
    access = create_access_token(
        user_id=user_id,
        username=src["username"],
        role=src["role_id"],
        org_scope=src.get("org_scope"),
        expires_delta=timedelta(minutes=settings.JWT_EXPIRY_MINUTES),
    )
    return {
        "access_token": access,
        "token_type": "bearer",
        "expires_in": settings.JWT_EXPIRY_MINUTES * 60,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Audit log
# ─────────────────────────────────────────────────────────────────────────────

async def write_audit_log(
    user_id: str,
    action: str,
    ip_address: Optional[str] = None,
    target_entity: Optional[str] = None,
    target_id: Optional[str] = None,
    details: Optional[dict] = None,
    *,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    http_method: Optional[str] = None,
    http_path: Optional[str] = None,
    status: str = "success",
) -> None:
    """
    Écrit une entrée dans le journal d'audit `idx-audit-log` (append-only).

    Champs capturés (durcis) :
      user_id, action, ip_address, user_agent, request_id,
      target_entity, target_id, http_method, http_path, status,
      details (dict libre), created_at.

    Aucune exception n'est propagée : un audit raté ne doit pas faire
    échouer une opération métier.
    """
    try:
        es = get_es_client()
        audit_entry = {
            "user_id": user_id,
            "action": action,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "request_id": request_id,
            "target_entity": target_entity,
            "target_id": target_id,
            "http_method": http_method,
            "http_path": http_path,
            "status": status,
            "details": details or {},
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        # "index" (sans id fourni) crée un nouveau document à chaque appel :
        # le journal d'audit est un flux d'événements, jamais mis à jour ni supprimé.
        await es.index(index="idx-audit-log", document=audit_entry)
    except Exception as exc:
        import logging
        logging.getLogger("audit").error("Audit log failed: %s", exc)
