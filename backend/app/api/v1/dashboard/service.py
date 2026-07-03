import logging

from app.core.elasticsearch import get_es_client

logger = logging.getLogger("dashboard.service")

_LOGS_INDEX   = "siem-logs-*"
_ALERTS_INDEX = "alert-mirror"


async def _count_alerts_from_pg() -> dict:
    """Lit les compteurs d'alertes directement depuis PostgreSQL."""
    from app.core.postgres import get_pg_pool
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        total = (await conn.fetchval(
            "SELECT COUNT(*) FROM alerts WHERE status = 'open'"
        )) or 0
        critical = (await conn.fetchval(
            "SELECT COUNT(*) FROM alerts WHERE status = 'open' AND level::text = 'CRITICAL'"
        )) or 0
        rows = await conn.fetch(
            "SELECT level::text AS level, COUNT(*) AS cnt "
            "FROM alerts WHERE status = 'open' GROUP BY level"
        )
    return {
        "total":    int(total),
        "critical": int(critical),
        "by_level": [{"niveau": r["level"], "count": r["cnt"]} for r in rows],
    }


async def _summary_from_pg_redis() -> dict:
    """Fallback complet : tout depuis PG + Redis."""
    pg = {"total": 0, "critical": 0, "by_level": []}
    try:
        pg = await _count_alerts_from_pg()
    except Exception as exc:
        logger.warning("PG fallback dashboard counts échoué : %s", exc)

    log_count = 0
    try:
        from app.core.redis_client import get_redis_client
        r = get_redis_client()
        log_count = await r.llen("recent_logs")
    except Exception:
        pass

    return {
        "total_logs_24h":     log_count,
        "total_alerts_open":  pg["total"],
        "critical_alerts":    pg["critical"],
        "alerts_by_level":    pg["by_level"],
        "log_volume_by_hour": [],
    }


async def get_summary() -> dict:
    es = get_es_client()

    # ── 1. Logs depuis Elasticsearch (fiable, index siem-logs-* toujours présent) ──
    total_logs_24h    = 0
    log_volume_by_hour = []
    try:
        logs_res = await es.count(
            index=_LOGS_INDEX,
            query={"range": {"@timestamp": {"gte": "now-24h"}}},
        )
        total_logs_24h = logs_res["count"]

        volume_res = await es.search(
            index=_LOGS_INDEX,
            query={"range": {"@timestamp": {"gte": "now-24h"}}},
            aggs={
                "logs_par_heure": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "1h",
                    }
                }
            },
            size=0,
        )
        hour_buckets = volume_res["aggregations"]["logs_par_heure"]["buckets"]
        log_volume_by_hour = [
            {"hour": b["key_as_string"], "count": b["doc_count"]}
            for b in hour_buckets
        ]
    except Exception as exc:
        logger.warning("ES logs indisponible : %s", exc)
        return await _summary_from_pg_redis()

    # ── 2. Alertes — ES en premier, fallback PG si 0 ou index absent ─────────────
    total_alerts_open = 0
    critical_alerts   = 0
    alerts_by_level   = []

    try:
        alerts_res = await es.search(
            index=_ALERTS_INDEX,
            query={"term": {"status": "open"}},
            aggs={"by_level": {"terms": {"field": "level", "size": 10}}},
            size=0,
        )
        critical_res = await es.count(
            index=_ALERTS_INDEX,
            query={
                "bool": {
                    "must": [
                        {"term": {"status": "open"}},
                        {"term": {"level": "CRITICAL"}},
                    ]
                }
            },
        )
        total_alerts_open = alerts_res["hits"]["total"]["value"]
        critical_alerts   = critical_res["count"]
        alerts_by_level   = [
            {"niveau": b["key"], "count": b["doc_count"]}
            for b in alerts_res["aggregations"]["by_level"]["buckets"]
        ]
    except Exception as exc:
        logger.warning("ES alert-mirror indisponible, fallback PG : %s", exc)

    # Fallback PG si ES n'a retourné aucune alerte (index vide ou absent)
    if total_alerts_open == 0:
        try:
            pg = await _count_alerts_from_pg()
            if pg["total"] > 0:
                total_alerts_open = pg["total"]
                critical_alerts   = pg["critical"]
                alerts_by_level   = pg["by_level"]
                logger.info(
                    "Alertes chargées depuis PG : %d ouvertes, %d critiques",
                    total_alerts_open, critical_alerts,
                )
        except Exception as exc:
            logger.warning("PG alert count fallback échoué : %s", exc)

    return {
        "total_logs_24h":     total_logs_24h,
        "total_alerts_open":  total_alerts_open,
        "critical_alerts":    critical_alerts,
        "alerts_by_level":    alerts_by_level,
        "log_volume_by_hour": log_volume_by_hour,
    }
