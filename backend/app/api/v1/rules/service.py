import json as _json

from app.core.postgres import get_pg_pool
from app.core.pg_utils import serialize_row

# Colonnes JSONB qui reviennent comme string depuis asyncpg sans codec JSON
_JSONB_COLS = ("conditions", "sources_required")


def _fix_jsonb(d: dict) -> dict:
    """Parse les colonnes JSONB retournées sous forme de string par asyncpg."""
    for key in _JSONB_COLS:
        v = d.get(key)
        if isinstance(v, str):
            try:
                d[key] = _json.loads(v)
            except Exception:
                d[key] = {}
    return d


async def list_rules(page: int = 1, size: int = 50) -> dict:
    pool = await get_pg_pool()
    offset = (page - 1) * size
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id, name, description, rule_type, conditions,
                      time_window_seconds, threshold_count,
                      alert_level::text AS alert_level,
                      confidence_score, mitre_tactic, mitre_technique,
                      is_active, created_by, created_at
               FROM correlation_rules
               ORDER BY created_at DESC
               LIMIT $1 OFFSET $2""",
            size,
            offset,
        )
        total = await conn.fetchval("SELECT COUNT(*) FROM correlation_rules")
    return {
        "total": int(total or 0),
        "items": [_fix_jsonb(serialize_row(r)) for r in rows],
    }


async def create_rule(data: dict, user_id: str) -> dict:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO correlation_rules
               (name, description, rule_type, conditions, time_window_seconds,
                threshold_count, alert_level, confidence_score, mitre_tactic,
                mitre_technique, is_active, created_by)
               VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11,$12::uuid)
               RETURNING *""",
            data.get("nom") or data.get("name"),
            data.get("description"),
            data.get("type") or data.get("rule_type", "threshold"),
            data.get("condition") or data.get("conditions", {}),
            data.get("fenetre_temporelle_s") or data.get("time_window_seconds"),
            data.get("threshold_count"),
            (data.get("niveau_alerte_genere") or data.get("alert_level", "WARNING")).upper(),
            data.get("confidence_score", 80),
            data.get("mitre_tactic"),
            data.get("mitre_technique"),
            data.get("active", data.get("is_active", True)),
            user_id,
        )
    return serialize_row(row)


async def toggle_rule(rule_id: str) -> dict:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """UPDATE correlation_rules
               SET is_active = NOT is_active
               WHERE id = $1::uuid
               RETURNING id, name, description, rule_type, conditions,
                         time_window_seconds, threshold_count,
                         alert_level::text AS alert_level,
                         confidence_score, mitre_tactic, mitre_technique,
                         is_active, created_by""",
            rule_id,
        )
    if row is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Règle introuvable")
    return _fix_jsonb(serialize_row(row))


async def update_rule(rule_id: str, data: dict) -> dict:
    from fastapi import HTTPException
    import json as _json2

    _COL_MAP = {
        "name":                ("name",                None),
        "description":         ("description",         None),
        "rule_type":           ("rule_type",           None),
        "conditions":          ("conditions",          "jsonb"),
        "time_window_seconds": ("time_window_seconds", None),
        "threshold_count":     ("threshold_count",     None),
        "alert_level":         ("alert_level",         "alert_level"),
        "confidence_score":    ("confidence_score",    None),
        "mitre_tactic":        ("mitre_tactic",        None),
        "mitre_technique":     ("mitre_technique",     None),
        "is_active":           ("is_active",           None),
    }

    set_clauses, values = [], []
    idx = 1
    for key, (col, cast) in _COL_MAP.items():
        if key not in data or data[key] is None:
            continue
        val = data[key]
        if col == "alert_level":
            val = str(val).upper()
        if cast:
            set_clauses.append(f"{col} = ${idx}::{cast}")
        else:
            set_clauses.append(f"{col} = ${idx}")
        values.append(val)
        idx += 1

    if not set_clauses:
        raise HTTPException(status_code=400, detail="Aucun champ à modifier")

    values.append(rule_id)
    sql = (
        f"UPDATE correlation_rules SET {', '.join(set_clauses)}, updated_at = NOW() "
        f"WHERE id = ${idx}::uuid "
        f"RETURNING id, name, description, rule_type, conditions, "
        f"time_window_seconds, threshold_count, "
        f"alert_level::text AS alert_level, confidence_score, "
        f"mitre_tactic, mitre_technique, is_active, created_by, "
        f"false_positive_count, trigger_count"
    )

    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(sql, *values)
    if row is None:
        raise HTTPException(status_code=404, detail="Règle introuvable")
    return _fix_jsonb(serialize_row(row))


async def delete_rule(rule_id: str) -> None:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM correlation_rules WHERE id = $1::uuid",
            rule_id,
        )
