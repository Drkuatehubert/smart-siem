"""
service.py — Logique métier d'authentification (durcie)

Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-01, RF-SEC-03 (audit), NFR-SEC-02, NFR-SEC-04 (lockout)

Durcissements par rapport à la version initiale :
  * `authenticate_user` est à durée constante (chemin unique avec bcrypt dummy
    si l'utilisateur n'existe pas) ⇒ empêche l'énumération par timing ;
  * un seul message d'erreur pour "user inconnu" et "mauvais mot de passe" ;
  * compteurs Redis `failed_login:<username>` et `failed_login:<ip>` ;
  * verrouillage du compte au-delà de `ACCOUNT_LOCKOUT_THRESHOLD` (423 Locked) ;
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
from app.core.redis_client import get_redis_client


# ─────────────────────────────────────────────────────────────────────
# Constantes d'erreur — ne jamais révéler pourquoi l'auth a échoué
# ─────────────────────────────────────────────────────────────────────

_ERR_INVALID = "Identifiants incorrects"
_ERR_LOCKED = "Compte temporairement verrouillé"


# ─────────────────────────────────────────────────────────────────────
# Lockout : compteurs Redis
# ─────────────────────────────────────────────────────────────────────

def _user_fail_key(username: str) -> str:
    return f"failed_login:user:{username.lower()}"

def _ip_fail_key(ip: str) -> str:
    return f"failed_login:ip:{ip}"

def _ttl_seconds() -> int:
    return settings.ACCOUNT_LOCKOUT_DURATION_MIN * 60


async def _bump_failed_login(username: str, ip: str) -> int:
    """Incrémente les compteurs et renvoie le compteur user (TTL = lockout duration)."""
    r = get_redis_client()
    pipe = r.pipeline()
    pipe.incr(_user_fail_key(username))
    pipe.expire(_user_fail_key(username), _ttl_seconds())
    pipe.incr(_ip_fail_key(ip))
    pipe.expire(_ip_fail_key(ip), _ttl_seconds())
    res = await pipe.execute()
    return int(res[0])


async def _reset_failed_login(username: str, ip: str) -> None:
    r = get_redis_client()
    await r.delete(_user_fail_key(username), _ip_fail_key(ip))


async def _is_locked(user_doc: Dict[str, Any], username: str, ip: str) -> bool:
    """Renvoie True si le compte (en ES) ou les compteurs Redis dépassent le seuil."""
    # 1. Champ explicite dans le doc utilisateur
    locked_until = user_doc.get("locked_until")
    if locked_until:
        try:
            until = datetime.fromisoformat(locked_until.replace("Z", "+00:00"))
            if until > datetime.now(timezone.utc):
                return True
        except Exception:
            pass
    # 2. Compteur Redis
    r = get_redis_client()
    user_count = await r.get(_user_fail_key(username))
    ip_count = await r.get(_ip_fail_key(ip))
    user_count = int(user_count) if user_count else 0
    ip_count = int(ip_count) if ip_count else 0
    return (
        user_count >= settings.ACCOUNT_LOCKOUT_THRESHOLD
        or ip_count >= settings.ACCOUNT_LOCKOUT_THRESHOLD
    )


# ─────────────────────────────────────────────────────────────────────
# Authentification (chemin à durée constante)
# ─────────────────────────────────────────────────────────────────────

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
      * lockout par compte ET par IP ;
      * audit `connexion_echouee` ou `connexion_reussie` systématique.

    Lève 401 (mauvais identifiants) ou 423 (locked).
    Renvoie le document utilisateur (avec son `id`) en cas de succès.
    """
    es = get_es_client()
    ip = ip or "0.0.0.0"

    # Recherche de l'utilisateur
    try:
        result = await es.search(
            index="idx-users",
            query={"term": {"username": username.lower()}},
            size=1,
        )
    except Exception:
        # En cas d'erreur ES on log un audit "infra" et on refuse
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

    # Garde timing constant : bcrypt dummy si user manquant
    if user is None:
        hash_password(os.urandom(16).hex())  # ~même coût qu'un vrai check
        await _bump_failed_login(username, ip)
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

    # Verrouillage ?
    if await _is_locked(user, username, ip):
        await write_audit_log(
            user_id=user_id,
            action="connexion_echouee",
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            status="failure",
            details={"username": username, "reason": "locked"},
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=_ERR_LOCKED,
        )

    # Vérification du mot de passe
    password_ok = verify_password(password, user["password_hash"])

    if not password_ok:
        attempts = await _bump_failed_login(username, ip)
        # Si on dépasse le seuil, on pose locked_until dans le doc
        if attempts >= settings.ACCOUNT_LOCKOUT_THRESHOLD:
            try:
                until = datetime.now(timezone.utc) + timedelta(
                    minutes=settings.ACCOUNT_LOCKOUT_DURATION_MIN
                )
                await es.update(
                    index="idx-users",
                    id=user_id,
                    doc={"locked_until": until.isoformat()},
                )
            except Exception:
                pass
            await write_audit_log(
                user_id=user_id,
                action="compte_verrouille",
                ip_address=ip,
                user_agent=user_agent,
                request_id=request_id,
                status="failure",
                details={"username": username, "attempts": attempts},
            )
        else:
            await write_audit_log(
                user_id=user_id,
                action="connexion_echouee",
                ip_address=ip,
                user_agent=user_agent,
                request_id=request_id,
                status="failure",
                details={"username": username, "reason": "bad_password", "attempts": attempts},
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_ERR_INVALID,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Succès : reset lockout + maj last_login_at
    await _reset_failed_login(username, ip)
    try:
        await es.update(
            index="idx-users",
            id=user_id,
            doc={
                "last_login_at": datetime.now(timezone.utc).isoformat(),
                "locked_until": None,
            },
        )
    except Exception:
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


# ─────────────────────────────────────────────────────────────────────
# Émission des tokens
# ─────────────────────────────────────────────────────────────────────

async def create_user_token(user: Dict[str, Any]) -> Dict[str, Any]:
    """
    Crée les tokens (access + refresh). Si MFA requis et activé,
    renvoie un mfa_token court sans access token.
    """
    # MFA ?
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


# ─────────────────────────────────────────────────────────────────────
# Audit log
# ─────────────────────────────────────────────────────────────────────

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
        await es.index(index="idx-audit-log", document=audit_entry)
    except Exception as exc:
        import logging
        logging.getLogger("audit").error("Audit log failed: %s", exc)
