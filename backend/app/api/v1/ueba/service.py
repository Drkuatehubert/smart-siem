"""ueba/service.py — Service UEBA : lecture et calcul des profils comportementaux."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.postgres import get_pg_pool
from app.core.pg_utils import serialize_row

log = logging.getLogger("ueba")

_WINDOW_DAYS = 7
_MIN_EVENTS = 3
_OFF_HOURS = set(range(0, 6)) | set(range(22, 24))
_PRIV_ACTIONS = ["privilege_escalation", "sudo", "root_login", "admin_access"]


def _parse_jsonb(val: Any) -> Any:
    """Convertit une string JSONB asyncpg en objet Python."""
    if isinstance(val, str):
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return val
    return val


async def list_profiles() -> dict:
    pool = await get_pg_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM ueba_profiles ORDER BY risk_score_current DESC"
        )
    items = []
    for r in rows:
        d = serialize_row(r)
        for field in ("typical_login_hours", "typical_source_ips", "typical_accessed_systems"):
            d[field] = _parse_jsonb(d.get(field))
        items.append(d)
    return {"items": items, "total": len(items)}


# ── Calcul du score de risque ──────────────────────────────────────────────────

def _risk_score(
    avg_daily: float,
    login_failed: int,
    off_pct: float,
    new_ip_count: int,
    priv_count: int,
    active_days: int,
) -> tuple[int, int]:
    score = 0
    anomalies = 0
    if login_failed / max(active_days, 1) > 5:
        score += 30
        anomalies += 1
    if off_pct > 0.30:
        score += 20
        anomalies += 1
    if new_ip_count > 3:
        score += 25
        anomalies += 1
    if priv_count > 0:
        score += 40
        anomalies += 1
    if avg_daily > 500:
        score += 15
        anomalies += 1
    return min(score, 100), anomalies


# ── Calcul des profils depuis Elasticsearch ───────────────────────────────────

async def compute_profiles() -> dict:
    """Re-calcule les profils UEBA depuis Elasticsearch et met à jour PostgreSQL."""
    from app.core.elasticsearch import get_es_client

    es = get_es_client()
    pool = await get_pg_pool()
    now = datetime.now(timezone.utc)
    period_start = (now - timedelta(days=_WINDOW_DAYS)).date()
    period_end = now.date()

    # ── Requête agrégation utilisateurs ──────────────────────────────────────
    user_q: dict[str, Any] = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{_WINDOW_DAYS}d"}}},
        "aggs": {
            "par_user": {
                "terms": {"field": "username", "size": 50, "min_doc_count": _MIN_EVENTS},
                "aggs": {
                    "heures": {
                        "terms": {
                            "script": {"source": "doc['@timestamp'].value.getHour()", "lang": "painless"},
                            "size": 24,
                        }
                    },
                    "ips": {"terms": {"field": "source_ip", "size": 20}},
                    "jours": {"date_histogram": {"field": "@timestamp", "calendar_interval": "1d"}},
                    "hosts": {"terms": {"field": "host", "size": 20}},
                    "off_hours": {
                        "filter": {
                            "script": {
                                "script": {
                                    "source": "int h=doc['@timestamp'].value.getHour(); return h>=22||h<6;",
                                    "lang": "painless",
                                }
                            }
                        }
                    },
                    "login_failed": {
                        "filter": {"terms": {"event_action": ["login_failed", "auth_failed", "login_failure"]}}
                    },
                    "privileged": {"filter": {"terms": {"event_action": _PRIV_ACTIONS}}},
                },
            }
        },
    }

    host_q: dict[str, Any] = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{_WINDOW_DAYS}d"}}},
        "aggs": {
            "par_host": {
                "terms": {"field": "host", "size": 30, "min_doc_count": _MIN_EVENTS},
                "aggs": {
                    "ips": {"terms": {"field": "source_ip", "size": 10}},
                    "jours": {"date_histogram": {"field": "@timestamp", "calendar_interval": "1d"}},
                    "off_hours": {
                        "filter": {
                            "script": {
                                "script": {
                                    "source": "int h=doc['@timestamp'].value.getHour(); return h>=22||h<6;",
                                    "lang": "painless",
                                }
                            }
                        }
                    },
                    "privileged": {"filter": {"terms": {"event_action": _PRIV_ACTIONS}}},
                },
            }
        },
    }

    try:
        res = await es.search(index="siem-logs-*", body=user_q)
        user_buckets = res["aggregations"]["par_user"]["buckets"]
    except Exception as exc:
        log.warning("ES user agg failed: %s", exc)
        user_buckets = []

    try:
        res = await es.search(index="siem-logs-*", body=host_q)
        host_buckets = res["aggregations"]["par_host"]["buckets"]
    except Exception as exc:
        log.warning("ES host agg failed: %s", exc)
        host_buckets = []

    user_count = 0
    host_count = 0

    async with pool.acquire() as conn:
        for bucket in user_buckets:
            username = str(bucket.get("key", "")).strip()
            if not username or username in ("", "null", "-"):
                continue
            total = bucket["doc_count"]
            days_b = bucket["jours"]["buckets"]
            active_days = max(sum(1 for d in days_b if d["doc_count"] > 0), 1)
            avg_daily = total / active_days

            hours = [b["key"] for b in bucket["heures"]["buckets"] if b["doc_count"] >= 2]
            ips = [b["key"] for b in bucket["ips"]["buckets"] if b["doc_count"] >= 2]
            hosts_list = [b["key"] for b in bucket.get("hosts", {}).get("buckets", []) if b["doc_count"] >= 2]
            off_count = bucket["off_hours"]["doc_count"]
            failed = bucket["login_failed"]["doc_count"]
            priv = bucket["privileged"]["doc_count"]

            off_pct = off_count / max(total, 1)
            peak_hours = [h for h in hours if h not in _OFF_HOURS]
            new_ips = max(0, len(bucket["ips"]["buckets"]) - len(ips))

            score, anomaly_count = _risk_score(avg_daily, failed, off_pct, new_ips, priv, active_days)

            prev = await conn.fetchval(
                "SELECT risk_score_current FROM ueba_profiles WHERE entity_id=$1 AND entity_type='user'::entity_type",
                username,
            )
            await conn.execute(
                "DELETE FROM ueba_profiles WHERE entity_id=$1 AND entity_type='user'::entity_type",
                username,
            )
            last_anomaly_at = now if anomaly_count > 0 else None
            await conn.execute(
                """INSERT INTO ueba_profiles (
                    entity_id, entity_type, profile_period_start, profile_period_end,
                    typical_login_hours, typical_source_ips, typical_accessed_systems,
                    avg_daily_events, risk_score_current, risk_score_previous,
                    anomaly_count_7d, last_anomaly_at, last_updated
                ) VALUES ($1, 'user'::entity_type, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb,
                    $7, $8, $9, $10, $11, NOW())""",
                username, period_start, period_end,
                json.dumps({"peak_hours": peak_hours, "off_hours": sorted(_OFF_HOURS)}),
                json.dumps(ips),
                json.dumps(hosts_list),
                round(avg_daily, 2), score, prev, anomaly_count, last_anomaly_at,
            )
            user_count += 1

        for bucket in host_buckets:
            hostname = str(bucket.get("key", "")).strip()
            if not hostname or hostname in ("", "null", "-"):
                continue
            total = bucket["doc_count"]
            days_b = bucket["jours"]["buckets"]
            active_days = max(sum(1 for d in days_b if d["doc_count"] > 0), 1)
            avg_daily = total / active_days

            ips = [b["key"] for b in bucket["ips"]["buckets"] if b["doc_count"] >= 2]
            off_count = bucket["off_hours"]["doc_count"]
            priv = bucket["privileged"]["doc_count"]
            off_pct = off_count / max(total, 1)
            new_ips = max(0, len(bucket["ips"]["buckets"]) - len(ips))

            score, anomaly_count = _risk_score(avg_daily, 0, off_pct, new_ips, priv, active_days)

            prev = await conn.fetchval(
                "SELECT risk_score_current FROM ueba_profiles WHERE entity_id=$1 AND entity_type='machine'::entity_type",
                hostname,
            )
            await conn.execute(
                "DELETE FROM ueba_profiles WHERE entity_id=$1 AND entity_type='machine'::entity_type",
                hostname,
            )
            last_anomaly_at = now if anomaly_count > 0 else None
            await conn.execute(
                """INSERT INTO ueba_profiles (
                    entity_id, entity_type, profile_period_start, profile_period_end,
                    typical_login_hours, typical_source_ips, typical_accessed_systems,
                    avg_daily_events, risk_score_current, risk_score_previous,
                    anomaly_count_7d, last_anomaly_at, last_updated
                ) VALUES ($1, 'machine'::entity_type, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb,
                    $7, $8, $9, $10, $11, NOW())""",
                hostname, period_start, period_end,
                json.dumps({"peak_hours": [], "off_hours": []}),
                json.dumps(ips),
                json.dumps([]),
                round(avg_daily, 2), score, prev, anomaly_count, last_anomaly_at,
            )
            host_count += 1

    log.info("UEBA compute done: %d users, %d machines", user_count, host_count)
    return {"users": user_count, "machines": host_count, "status": "done"}
