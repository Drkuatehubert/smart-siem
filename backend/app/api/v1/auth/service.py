from __future__ import annotations

import json
import os
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import HTTPException, status

from app.config import settings
from app.core.postgres import get_pg_pool
from app.core.rbac import normalize_role
from app.core.security import (
    create_access_token,
    create_mfa_token,
    create_refresh_token,
    hash_password,
    verify_password,
)
from app.core.redis_client import get_redis_client


# ─────────────────────────────────────────────────────────────────────────────
# Constantes d'erreur — ne jamais révéler pourquoi l'auth a échoué
# ─────────────────────────────────────────────────────────────────────────────

_ERR_INVALID = "Identifiants incorrects"
_ERR_LOCKED = "Compte temporairement verrouillé"


# ─────────────────────────────────────────────────────────────────────────────
# Lockout : compteurs Redis
# ─────────────────────────────────────────────────────────────────────────────

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
    # 1. Champ locked_until depuis PG (datetime tz-aware ou None)
    locked_until = user_doc.get("locked_until")
    if locked_until is not None:
        until = locked_until if locked_until.tzinfo else locked_until.replace(tzinfo=timezone.utc)
        if until > datetime.now(timezone.utc):
            return True
    # 2. Compteurs Redis
    r = get_redis_client()
    user_count = await r.get(_user_fail_key(username))
    ip_count = await r.get(_ip_fail_key(ip))
    user_count = int(user_count) if user_count else 0
    ip_count = int(ip_count) if ip_count else 0
    return (
        user_count >= settings.ACCOUNT_LOCKOUT_THRESHOLD
        or ip_count >= settings.ACCOUNT_LOCKOUT_THRESHOLD
    )


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
    ip = ip or "0.0.0.0"
    pool = await get_pg_pool()

    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """SELECT id, username, email, hashed_password, role,
                          mfa_secret, mfa_enabled, org_scope, is_active,
                          last_login_at, failed_login_count, locked_until
                   FROM users
                   WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($1)""",
                username,
            )
    except Exception:
        await write_audit_log(
            user_id="anonymous",
            action="connexion_echouee",
            ip_address=ip,
            user_agent=user_agent,
            request_id=request_id,
            details={"username": username, "reason": "pg_unreachable"},
        )
        raise HTTPException(status_code=503, detail="Service temporairement indisponible")

    user = dict(row) if row else None
    user_id = str(user["id"]) if user else None

    # Timing constant : bcrypt dummy si user manquant
    if user is None:
        hash_password(os.urandom(16).hex())
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

    # Vérification du mot de passe (colonne PG : hashed_password)
    password_ok = verify_password(password, user["hashed_password"])

    if not password_ok:
        attempts = await _bump_failed_login(username, ip)
        if attempts >= settings.ACCOUNT_LOCKOUT_THRESHOLD:
            until = datetime.now(timezone.utc) + timedelta(
                minutes=settings.ACCOUNT_LOCKOUT_DURATION_MIN
            )
            try:
                async with pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE users SET locked_until=$1 WHERE id=$2",
                        until, user["id"],
                    )
            except Exception:
                pass
            await write_audit_log(
                user_id=user_id,
                action="compte_verrouille",
                ip_address=ip,
                user_agent=user_agent,
                request_id=request_id,
                status="denied",
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
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET last_login_at=$1, locked_until=NULL, failed_login_count=0 WHERE id=$2",
                datetime.now(timezone.utc), user["id"],
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
        details={"username": user["username"], "role": user.get("role")},
    )

    user["id"] = user_id  # convertit UUID → str
    return user


# ─────────────────────────────────────────────────────────────────────────────
# Émission des tokens
# ─────────────────────────────────────────────────────────────────────────────

async def create_user_token(user: Dict[str, Any]) -> Dict[str, Any]:
    """Crée les tokens (access + refresh). Si MFA requis et activé,
    renvoie un mfa_token court sans access token.
    """
    if settings.MFA_REQUIRED and user.get("mfa_enabled"):
        mfa_token = create_mfa_token(user["id"])
        return {
            "mfa_required": True,
            "mfa_token": mfa_token,
            "token_type": "mfa",
            "user": {
                "user_id": user["id"],
                "username": user["username"],
                "role": user.get("role"),
                "org_scope": user.get("org_scope"),
                "is_active": user.get("is_active", True),
            },
        }

    access = create_access_token(
        user_id=user["id"],
        username=user["username"],
        role=normalize_role(user["role"]),
        org_scope=user.get("org_scope"),
        expires_delta=timedelta(minutes=settings.JWT_EXPIRY_MINUTES),
    )
    refresh = create_refresh_token(user["id"])
    normalized_role = normalize_role(user["role"])
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": settings.JWT_EXPIRY_MINUTES * 60,
        "user": {
            "user_id": user["id"],
            "username": user["username"],
            "email": user.get("email"),
            "role": normalized_role,
            "org_scope": user.get("org_scope"),
            "is_active": user.get("is_active", True),
        },
    }


async def refresh_user_token(user_id: str) -> Dict[str, Any]:
    """Émet un nouveau access token à partir d'un user_id (validé par refresh JWT)."""
    pool = await get_pg_pool()
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, username, email, role, org_scope, is_active FROM users WHERE id=$1::uuid",
                user_id,
            )
    except Exception:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    if row is None:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    user = dict(row)
    if not user.get("is_active", False):
        raise HTTPException(status_code=403, detail="Compte désactivé")
    access = create_access_token(
        user_id=user_id,
        username=user["username"],
        role=normalize_role(user["role"]),
        org_scope=user.get("org_scope"),
        expires_delta=timedelta(minutes=settings.JWT_EXPIRY_MINUTES),
    )
    return {
        "access_token": access,
        "token_type": "bearer",
        "expires_in": settings.JWT_EXPIRY_MINUTES * 60,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Audit log → PostgreSQL
# ─────────────────────────────────────────────────────────────────────────────

_AUDIT_ACTION_MAP: Dict[str, str] = {
    "connexion_reussie":   "user_login",
    "connexion_echouee":   "user_login",
    "compte_verrouille":   "user_login",
    "user_logout":         "user_logout",
    "user_created":        "user_created",
    "user_deleted":        "user_deleted",
    "role_changed":        "role_changed",
    "password_changed":    "password_changed",
    "mfa_enrolled":        "mfa_enrolled",
    "consultation_alerte": "alert_acknowledged",
    "traitement_alerte":   "alert_acknowledged",
    "alert_acknowledged":  "alert_acknowledged",
    "alert_closed":        "alert_closed",
    "alert_escalated":     "alert_escalated",
    "incident_created":    "incident_created",
    "incident_assigned":   "incident_assigned",
    "incident_resolved":   "incident_resolved",
    "rule_created":        "rule_created",
    "rule_modified":       "rule_modified",
    "rule_deleted":        "rule_deleted",
    "rule_toggled":        "rule_toggled",
    "playbook_executed":   "playbook_executed",
    "playbook_created":    "playbook_created",
    "log_exported":        "log_exported",
    "report_generated":    "report_generated",
    "config_changed":      "config_changed",
    "api_key_created":     "api_key_created",
}

_VALID_ROLES = {"reader", "analyst", "rssi", "auditor", "admin"}
_VALID_RESULTS = {"success", "failure", "denied"}


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
    """Écrit dans audit_logs (PostgreSQL). Aucune exception propagée."""
    import logging as _logging
    try:
        pg_action = _AUDIT_ACTION_MAP.get(action)
        if pg_action is None:
            return

        pg_result = status if status in _VALID_RESULTS else "success"
        d = details or {}
        username_snap: str = d.get("username") or "anonymous"
        role_raw = str(d.get("role") or "reader")
        role_snap: str = role_raw if role_raw in _VALID_ROLES else "reader"

        pg_user_id = None
        if user_id and user_id != "anonymous":
            try:
                pg_user_id = _uuid.UUID(str(user_id))
            except ValueError:
                pg_user_id = None

        metadata = {
            **d,
            "request_id": request_id,
            "http_method": http_method,
            "http_path": http_path,
        }

        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO audit_logs
                   (user_id, username_snapshot, role_snapshot, action,
                    resource_type, resource_id, ip_address, user_agent, result, metadata)
                   VALUES ($1, $2, $3::user_role, $4::audit_action,
                           $5, $6, $7, $8, $9::action_result, $10::jsonb)""",
                pg_user_id,
                username_snap,
                role_snap,
                pg_action,
                target_entity,
                target_id,
                ip_address,
                user_agent,
                pg_result,
                json.dumps(metadata),
            )
    except Exception as exc:
        _logging.getLogger("audit").error("Audit log failed: %s", exc)
