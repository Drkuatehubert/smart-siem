"""
alerts/services.py

Points d'intégration :
  - PostgreSQL (alerts, correlation_rules, playbook_executions) via DBSession + RLS
  - Elasticsearch (siem-logs-*) via get_es_client()
  - Module playbook → services.execute() pour déclenchement auto
"""
import asyncpg
from uuid import UUID
from typing import Optional
from app.core.database import DBSession, get_pool
from app.core.elasticsearch import get_es_client, ES_INDEX_PATTERN
from app.core.rbac import CurrentUser
from app.alerts.models import AlertFilter, AlertDetail


async def list_alerts(filters: AlertFilter, user: CurrentUser) -> dict:
    """
    Recherche multi-critères dans PostgreSQL alerts.
    Le RLS de 03_rbac.sql filtre automatiquement selon le rôle.
    Tous les filtres sont optionnels — leur absence ne casse pas la query.
    """
    conditions = ["1=1"]   # Base toujours vraie
    params = []
    idx = 1

    if filters.from_date:
        conditions.append(f"triggered_at >= ${idx}")
        params.append(filters.from_date); idx += 1

    if filters.to_date:
        conditions.append(f"triggered_at <= ${idx}")
        params.append(filters.to_date); idx += 1

    if filters.level:
        conditions.append(f"level = ${idx}")
        params.append(filters.level.value); idx += 1

    if filters.status:
        conditions.append(f"status = ${idx}")
        params.append(filters.status.value); idx += 1

    if filters.source_ip:
        conditions.append(f"${idx}::inet = ANY(source_ips::inet[])")
        params.append(filters.source_ip); idx += 1

    if filters.dest_ip:
        conditions.append(f"${idx}::inet = ANY(dest_ips::inet[])")
        params.append(filters.dest_ip); idx += 1

    if filters.mitre_tactic:
        conditions.append(f"mitre_tactic ILIKE ${idx}")
        params.append(f"%{filters.mitre_tactic}%"); idx += 1

    if filters.username:
        conditions.append(f"${idx} = ANY(usernames)")
        params.append(filters.username); idx += 1

    if filters.affected_host:
        conditions.append(f"${idx} = ANY(affected_hosts)")
        params.append(filters.affected_host); idx += 1

    # Pagination
    offset = (filters.page - 1) * filters.page_size
    where  = " AND ".join(conditions)
    query  = f"""
        SELECT *, COUNT(*) OVER() AS total_count
        FROM alerts
        WHERE {where}
        ORDER BY triggered_at DESC
        LIMIT ${idx} OFFSET ${idx+1}
    """
    params += [filters.page_size, offset]

    async with DBSession(user) as conn:   # RLS injecté automatiquement
        rows = await conn.fetch(query, *params)

    total = rows[0]["total_count"] if rows else 0
    return {
        "total":   total,
        "page":    filters.page,
        "items":   [dict(r) for r in rows]
    }


async def get_alert_detail(alert_id: UUID, user: CurrentUser) -> AlertDetail:
    """
    Route composite :
    1. Récupère l'alerte depuis PostgreSQL
    2. Récupère les logs ES liés via correlated_event_ids
    3. Récupère la règle de corrélation associée
    4. Récupère les exécutions de playbooks liées
    5. Construit un résumé MITRE des logs
    """
    async with DBSession(user) as conn:

        # ── 1. Alerte principale ──────────────────────────────
        alert = await conn.fetchrow(
            "SELECT * FROM alerts WHERE id = $1", alert_id
        )
        if not alert:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Alerte introuvable")
        alert = dict(alert)

        # ── 3. Règle de corrélation ───────────────────────────
        rule = None
        if alert.get("rule_id"):
            rule_row = await conn.fetchrow(
                "SELECT * FROM correlation_rules WHERE id = $1",
                alert["rule_id"]
            )
            rule = dict(rule_row) if rule_row else None

        # ── 4. Exécutions de playbooks ────────────────────────
        exec_rows = await conn.fetch(
            """
            SELECT pe.*, p.name AS playbook_name, p.playbook_type
            FROM playbook_executions pe
            JOIN playbooks p ON pe.playbook_id = p.id
            WHERE pe.alert_id = $1
            ORDER BY pe.started_at DESC
            """,
            alert_id
        )
        executions = [dict(r) for r in exec_rows]

    # ── 2. Logs Elasticsearch ─────────────────────────────────
    correlated_logs = []
    mitre_summary   = {}
    event_ids       = alert.get("correlated_event_ids") or []

    if event_ids:
        es = get_es_client()
        es_result = await es.search(
            index=ES_INDEX_PATTERN,
            query={"ids": {"values": event_ids}},
            size=len(event_ids)
        )
        correlated_logs = [
            hit["_source"] | {"_id": hit["_id"]}
            for hit in es_result["hits"]["hits"]
        ]

        # Résumé MITRE depuis les logs
        mitre_summary = _build_mitre_summary(correlated_logs)

    return AlertDetail(
        alert=alert,
        correlated_logs=correlated_logs,
        correlation_rule=rule,
        playbook_executions=executions,
        mitre_summary=mitre_summary
    )


def _build_mitre_summary(logs: list[dict]) -> dict:
    """Agrège les tactiques et techniques MITRE trouvées dans les logs ES."""
    tactics    = {}
    techniques = {}
    for log in logs:
        tactic = log.get("mitre_tactic")
        tech   = log.get("mitre_technique")
        if tactic:
            tactics[tactic] = tactics.get(tactic, 0) + 1
        if tech:
            techniques[tech] = techniques.get(tech, 0) + 1
    return {"tactics": tactics, "techniques": techniques}


async def update_alert(
    alert_id: UUID,
    updates: dict,
    user: CurrentUser
) -> dict:
    """Met à jour le statut ou les notes d'une alerte."""
    allowed_fields = {"status", "notes", "acknowledged_by", "acknowledged_at",
                      "is_false_positive", "assigned_to"}
    set_clauses = []
    params = []
    idx = 1

    for field, value in updates.items():
        if field in allowed_fields and value is not None:
            set_clauses.append(f"{field} = ${idx}")
            params.append(value); idx += 1

    if not set_clauses:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Aucun champ valide à mettre à jour")

    params.append(alert_id)
    query = f"""
        UPDATE alerts
        SET {', '.join(set_clauses)}, updated_at = NOW()
        WHERE id = ${idx}
        RETURNING *
    """
    async with DBSession(user) as conn:
        row = await conn.fetchrow(query, *params)

    return dict(row)