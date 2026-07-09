"""service.py – Lecture et export du journal d'audit (PostgreSQL)."""
from __future__ import annotations

import csv
import io
import json
from typing import Any, AsyncGenerator, Dict, List, Optional

from app.core.postgres import get_pg_pool
from app.core.pg_utils import serialize_row


async def get_audit_logs(
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    page: int = 1,
    size: int = 50,
) -> Dict[str, Any]:
    size = max(1, min(size, 500))
    offset = (page - 1) * size

    conditions: List[str] = []
    params: List[Any] = []

    if user_id:
        params.append(user_id)
        conditions.append(f"al.user_id = ${len(params)}::uuid")
    if action:
        params.append(action)
        conditions.append(f"al.action::text = ${len(params)}")
    if from_date:
        params.append(from_date)
        conditions.append(f"al.performed_at >= ${len(params)}::timestamptz")
    if to_date:
        params.append(to_date)
        conditions.append(f"al.performed_at <= ${len(params)}::timestamptz")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    params.append(size)
    limit_idx = len(params)
    params.append(offset)
    offset_idx = len(params)

    query = f"""
        SELECT al.id, al.performed_at, al.action::text AS action,
               al.result::text AS result, al.ip_address, al.user_agent,
               al.resource_type, al.resource_id, al.metadata,
               al.user_id::text AS user_id,
               u.username, u.role::text AS role_snapshot
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        {where}
        ORDER BY al.performed_at DESC
        LIMIT ${limit_idx} OFFSET ${offset_idx}
    """

    count_query = f"""
        SELECT COUNT(*) FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        {where}
    """

    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
        total = await conn.fetchval(count_query, *params[: len(params) - 2])

    return {
        "total": total,
        "page": page,
        "size": size,
        "results": [serialize_row(r) for r in rows],
    }


async def get_failed_logins(
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    page: int = 1,
    size: int = 50,
) -> Dict[str, Any]:
    return await get_audit_logs(
        action="user_login",
        from_date=from_date,
        to_date=to_date,
        page=page,
        size=size,
    )


async def export_audit_logs(
    fmt: str,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    max_rows: int = 50_000,
) -> AsyncGenerator[bytes, None]:
    """Stream l'export CSV ou JSONL depuis PostgreSQL."""
    conditions: List[str] = []
    params: List[Any] = []
    if from_date:
        params.append(from_date)
        conditions.append(f"performed_at >= ${len(params)}::timestamptz")
    if to_date:
        params.append(to_date)
        conditions.append(f"performed_at <= ${len(params)}::timestamptz")

    params.append(max_rows)
    limit_idx = len(params)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    query = f"""
        SELECT al.id, al.performed_at, al.user_id::text, al.action::text,
               al.result::text, al.ip_address, al.user_agent,
               al.resource_type, al.resource_id,
               al.metadata, u.username
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        {where}
        ORDER BY al.performed_at ASC
        LIMIT ${limit_idx}
    """

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "id", "performed_at", "user_id", "username", "action", "result",
            "ip_address", "user_agent", "resource_type", "resource_id", "details",
        ])
        yield buf.getvalue().encode("utf-8")
        buf.seek(0)
        buf.truncate(0)
    elif fmt != "jsonl":
        raise ValueError(f"format inconnu : {fmt}")
    else:
        yield b""

    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)

    for row in rows:
        r = serialize_row(row)
        if fmt == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow([
                r.get("id"), r.get("performed_at"), r.get("user_id"),
                r.get("username"), r.get("action"), r.get("result"),
                r.get("ip_address"), r.get("user_agent"),
                r.get("resource_type"), r.get("resource_id"),
                json.dumps(r.get("metadata") or {}, ensure_ascii=False, default=str),
            ])
            yield buf.getvalue().encode("utf-8")
        else:
            yield (json.dumps(r, ensure_ascii=False, default=str) + "\n").encode("utf-8")
