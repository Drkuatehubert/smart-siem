"""service.py – Gestion des utilisateurs via PostgreSQL."""
from __future__ import annotations

import logging
import secrets
import string
from typing import Any, Dict, Optional

from fastapi import HTTPException

from app.core.postgres import get_pg_pool
from app.core.pg_utils import serialize_row
from app.core.security import hash_password

logger = logging.getLogger("users.service")


async def list_users(page: int = 1, size: int = 50) -> Dict[str, Any]:
    size = max(1, min(size, 500))
    offset = (page - 1) * size
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id, username, email, role::text AS role, mfa_enabled, org_scope,
                      is_active, last_login_at, failed_login_count, locked_until,
                      created_at, created_by
               FROM users ORDER BY created_at DESC NULLS LAST LIMIT $1 OFFSET $2""",
            size, offset,
        )
        total = await conn.fetchval("SELECT COUNT(*) FROM users")
    return {
        "total": total,
        "page": page,
        "size": size,
        "results": [serialize_row(r) for r in rows],
    }


async def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT id, username, email, role::text AS role, mfa_enabled, org_scope,
                      is_active, last_login_at, failed_login_count, locked_until,
                      created_at, created_by
               FROM users WHERE id = $1::uuid""",
            user_id,
        )
    return serialize_row(row) if row else None


async def count_active_admins() -> int:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        return await conn.fetchval(
            "SELECT COUNT(*) FROM users WHERE is_active = true AND role = 'admin'::user_role"
        )


async def create_user(data: Dict[str, Any]) -> Dict[str, Any]:
    pool = await get_pg_pool()
    mfa_secret = "".join(
        secrets.choice(string.ascii_uppercase + string.digits) for _ in range(32)
    )
    raw_password = data.get("password", "")
    role = data.get("role", "analyst")

    async with pool.acquire() as conn:
        try:
            row = await conn.fetchrow(
                """INSERT INTO users
                   (username, email, hashed_password, role, mfa_secret, mfa_enabled,
                    is_active, org_scope)
                   VALUES ($1, $2, $3, $4::user_role, $5, $6, true, $7)
                   RETURNING id, username, email, role::text AS role, mfa_enabled,
                             is_active, org_scope, last_login_at, failed_login_count,
                             locked_until, created_at""",
                data["username"],
                data.get("email"),
                hash_password(raw_password),
                role,
                mfa_secret,
                bool(data.get("mfa_enabled", False)),
                data.get("org_scope"),
            )
        except Exception as exc:
            err = str(exc)
            if any(k in err for k in ("uq_users_username", "uq_users_email",
                                       "UniqueViolation", "duplicate key")):
                raise HTTPException(
                    status_code=409, detail="Nom d'utilisateur ou email déjà pris"
                )
            raise
    return serialize_row(row)


async def update_user(user_id: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    patch = {k: v for k, v in patch.items() if v is not None}
    if not patch:
        return await get_user_by_id(user_id)

    allowed = {"email", "role", "org_scope", "is_active"}
    safe = {k: v for k, v in patch.items() if k in allowed}
    if not safe:
        return await get_user_by_id(user_id)

    pool = await get_pg_pool()
    sets: list[str] = []
    params: list[Any] = []
    for key, val in safe.items():
        params.append(val)
        if key == "role":
            sets.append(f"role = ${len(params)}::user_role")
        else:
            sets.append(f"{key} = ${len(params)}")

    params.append(user_id)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"""UPDATE users SET {", ".join(sets)}
                WHERE id = ${len(params)}::uuid
                RETURNING id, username, email, role::text AS role, mfa_enabled,
                          is_active, org_scope, last_login_at, failed_login_count,
                          locked_until, created_at""",
            *params,
        )
    return serialize_row(row) if row else None


async def delete_user(user_id: str) -> None:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM users WHERE id = $1::uuid", user_id
        )
    if result == "DELETE 0":
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")


async def set_user_active(user_id: str, is_active: bool) -> Optional[Dict[str, Any]]:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """UPDATE users SET is_active = $1
               WHERE id = $2::uuid
               RETURNING id, username, email, role::text AS role, mfa_enabled,
                         is_active, org_scope, last_login_at, failed_login_count,
                         locked_until, created_at""",
            is_active, user_id,
        )
    return serialize_row(row) if row else None


async def update_role(user_id: str, role: str) -> Dict[str, Any]:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """UPDATE users SET role = $1::user_role
               WHERE id = $2::uuid
               RETURNING id, username, email, role::text AS role, mfa_enabled,
                         is_active, org_scope, last_login_at, failed_login_count,
                         locked_until, created_at""",
            role, user_id,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    return serialize_row(row)


async def reset_password(user_id: str) -> Dict[str, Any]:
    chars = string.ascii_letters + string.digits + "!@#"
    temp_pw = "".join(secrets.choice(chars) for _ in range(12))
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """UPDATE users SET hashed_password = $1, must_change_password = true
               WHERE id = $2::uuid""",
            hash_password(temp_pw),
            user_id,
        )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    return {"temp_password": temp_pw}


async def get_user_activity(user_id: str) -> Dict[str, Any]:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        stats = await conn.fetchrow(
            """SELECT
               COUNT(*) FILTER (WHERE action = 'user_login' AND result = 'success') AS logins_ok,
               COUNT(*) FILTER (WHERE action = 'user_login' AND result != 'success') AS logins_fail,
               COUNT(*) FILTER (WHERE action = 'alert_acknowledged') AS alerts_ack,
               COUNT(*) FILTER (WHERE action = 'playbook_executed') AS soar_actions,
               COUNT(*) FILTER (WHERE action IN ('log_exported','report_generated')) AS exports
               FROM audit_logs
               WHERE user_id = $1::uuid
               AND performed_at > NOW() - INTERVAL '7 days'""",
            user_id,
        )
        days_rows = await conn.fetch(
            """SELECT to_char(performed_at AT TIME ZONE 'UTC', 'Dy') AS day,
                      COUNT(*) AS cnt
               FROM audit_logs
               WHERE user_id = $1::uuid
               AND performed_at > NOW() - INTERVAL '7 days'
               GROUP BY 1
               ORDER BY MIN(performed_at)""",
            user_id,
        )
        recent = await conn.fetch(
            """SELECT action::text, result::text, resource_type, resource_id, performed_at
               FROM audit_logs
               WHERE user_id = $1::uuid
               ORDER BY performed_at DESC LIMIT 10""",
            user_id,
        )

    lf = int(stats["logins_fail"] or 0)
    la = int(stats["alerts_ack"] or 0)
    score = min(100, lf * 10 + (0 if la > 0 else 5))

    return {
        "score": score,
        "level": (
            "critique" if score > 50
            else "élevé" if score > 30
            else "modéré" if score > 10
            else "faible"
        ),
        "logins_success": int(stats["logins_ok"] or 0),
        "logins_failed": lf,
        "alerts_acknowledged": la,
        "soar_actions": int(stats["soar_actions"] or 0),
        "exports": int(stats["exports"] or 0),
        "activity_by_day": [
            {"day": r["day"], "count": int(r["cnt"])} for r in days_rows
        ],
        "recent_actions": [
            {
                "time": r["performed_at"].isoformat() if r["performed_at"] else "",
                "action": r["action"],
                "result": r["result"],
                "detail": " ".join(
                    filter(None, [r["resource_type"], r["resource_id"]])
                ),
            }
            for r in recent
        ],
    }
