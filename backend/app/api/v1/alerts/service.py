import json
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("alerts.service")

_ALERT_INDEX = "alert-mirror"


def _hit_to_alert(hit: dict) -> dict:
    src = hit["_source"]
    return {
        "id":               hit["_id"],
        "pg_alert_id":      src.get("pg_alert_id"),
        "level":            src.get("level"),
        "status":           src.get("status"),
        "title":            src.get("title"),
        "rule_name":        src.get("rule_name"),
        "mitre_tactic":     src.get("mitre_tactic"),
        "source_ips":       src.get("source_ips", []),
        "affected_hosts":   src.get("affected_hosts", []),
        "confidence_score": src.get("confidence_score"),
        "triggered_at":     src.get("@timestamp"),
    }


def _pg_row_to_alert(row) -> dict:
    data = dict(row)
    source_ips = data.get("source_ips") or []
    affected_hosts = data.get("affected_hosts") or []
    if isinstance(source_ips, str):
        try:
            source_ips = json.loads(source_ips)
        except Exception:
            source_ips = []
    if isinstance(affected_hosts, str):
        try:
            affected_hosts = json.loads(affected_hosts)
        except Exception:
            affected_hosts = []
    triggered_at = data.get("triggered_at")
    if hasattr(triggered_at, "isoformat"):
        triggered_at = triggered_at.isoformat()
    alert_id = str(data.get("id", ""))
    return {
        "id":               alert_id,
        "pg_alert_id":      alert_id,
        "level":            data.get("level") or "INFO",
        "status":           data.get("status") or "open",
        "title":            data.get("title"),
        "rule_name":        data.get("rule_name"),
        "mitre_tactic":     data.get("mitre_tactic"),
        "source_ips":       source_ips if isinstance(source_ips, list) else [],
        "affected_hosts":   affected_hosts if isinstance(affected_hosts, list) else [],
        "confidence_score": data.get("confidence_score"),
        "triggered_at":     triggered_at,
    }


async def _list_alerts_from_pg(niveau, statut, page: int, size: int) -> dict:
    """Fallback PostgreSQL quand ES est hors ligne."""
    try:
        from app.core.postgres import get_pg_pool
        pool = await get_pg_pool()
        conditions: list[str] = []
        params: list = []
        if niveau:
            params.append(niveau.upper())
            conditions.append(f"UPPER(a.level::text) = ${len(params)}")
        if statut:
            params.append(statut)
            conditions.append(f"a.status::text = ${len(params)}")
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        count_params = list(params)
        params += [size, (page - 1) * size]
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                f"""SELECT a.id, a.title, a.level, a.status, a.mitre_tactic,
                           a.source_ips, a.affected_hosts, a.confidence_score,
                           a.triggered_at, r.name AS rule_name
                    FROM alerts a
                    LEFT JOIN correlation_rules r ON a.rule_id = r.id
                    {where}
                    ORDER BY a.triggered_at DESC NULLS LAST
                    LIMIT ${len(params) - 1} OFFSET ${len(params)}""",
                *params,
            )
            total = (await conn.fetchval(
                f"SELECT COUNT(*) FROM alerts a {where}", *count_params
            )) or 0
        return {
            "total":   total,
            "page":    page,
            "size":    size,
            "results": [_pg_row_to_alert(r) for r in rows],
        }
    except Exception as exc:
        logger.warning("PG fallback /alerts échoué : %s", exc)
        return {"total": 0, "page": page, "size": size, "results": []}


async def list_alerts(
    niveau=None, statut=None, page=1, size=50, org_scope=None
) -> dict:
    return await _list_alerts_from_pg(niveau, statut, page, size)


async def get_alert(alert_id: str) -> Optional[dict]:
    es = get_es_client()
    try:
        res = await es.search(
            index=_ALERT_INDEX,
            query={"term": {"pg_alert_id": alert_id}},
            size=1,
        )
        hits = res["hits"]["hits"]
        if hits:
            return _hit_to_alert(hits[0])
    except Exception as exc:
        logger.warning("ES indisponible pour get_alert : %s", exc)

    # Fallback PG
    try:
        from app.core.postgres import get_pg_pool
        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """SELECT a.id, a.title, a.level, a.status, a.mitre_tactic,
                          a.source_ips, a.affected_hosts, a.confidence_score,
                          a.triggered_at, r.name AS rule_name
                   FROM alerts a
                   LEFT JOIN correlation_rules r ON a.rule_id = r.id
                   WHERE a.id = $1::uuid""",
                alert_id,
            )
        return _pg_row_to_alert(row) if row else None
    except Exception as exc:
        logger.warning("PG fallback get_alert échoué : %s", exc)
        return None


async def acknowledge_alert(alert_id: str, acknowledged_by: str) -> dict:
    """Acquitte une alerte : status → 'investigating', enregistre l'analyste."""
    now = datetime.now(timezone.utc).isoformat()
    try:
        from app.core.postgres import get_pg_pool
        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """UPDATE alerts
                   SET status = 'investigating',
                       acknowledged_at = NOW(),
                       acknowledged_by = $2::uuid
                   WHERE id = $1::uuid""",
                alert_id, acknowledged_by,
            )
    except Exception as exc:
        logger.warning("PG acknowledge_alert échoué : %s", exc)

    # ES mise à jour non-bloquante
    try:
        from app.core.elasticsearch import get_es_client
        es = get_es_client()
        res = await es.search(
            index=_ALERT_INDEX,
            query={"term": {"pg_alert_id": alert_id}},
            size=1,
        )
        hits = res["hits"]["hits"]
        if hits:
            await es.update(
                index=_ALERT_INDEX,
                id=hits[0]["_id"],
                doc={"status": "investigating"},
            )
    except Exception:
        pass

    return {"id": alert_id, "status": "investigating", "acknowledged_at": now}


async def update_alert_status(
    alert_id: str,
    statut: str,
    assigned_to: Optional[str],
    commentaires: Optional[str],
) -> dict:
    # PG — source de vérité
    try:
        from app.core.postgres import get_pg_pool
        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE alerts SET status = $1::alert_status WHERE id = $2::uuid",
                statut, alert_id,
            )
    except Exception as exc:
        logger.warning("PG update_alert_status échoué : %s", exc)

    # ES — mise à jour secondaire, non bloquante
    try:
        from app.core.elasticsearch import get_es_client
        es = get_es_client()
        res = await es.search(
            index=_ALERT_INDEX,
            query={"term": {"pg_alert_id": alert_id}},
            size=1,
        )
        hits = res["hits"]["hits"]
        if hits:
            await es.update(
                index=_ALERT_INDEX,
                id=hits[0]["_id"],
                doc={"status": statut},
            )
    except Exception as exc:
        logger.warning("ES update_alert_status échoué (non bloquant) : %s", exc)

    return {"id": alert_id, "status": statut}
