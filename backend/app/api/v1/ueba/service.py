"""ueba/service.py — Service UEBA : lecture et calcul des profils comportementaux (ML)."""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.postgres import get_pg_pool
from app.core.pg_utils import serialize_row

log = logging.getLogger("ueba")


def _parse_jsonb(val: Any) -> Any:
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


# ── Découverte des entités dans ES ────────────────────────────────────────────

async def _discover_entities(es) -> list[tuple[str, str]]:
    """Retourne la liste (entity_id, entity_type) trouvée dans ES sur 30 jours."""
    query: dict = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-30d"}}},
        "aggs": {
            "users": {"terms": {"field": "username",  "size": 100, "min_doc_count": 10}},
            "hosts": {"terms": {"field": "host",      "size":  50, "min_doc_count": 10}},
        },
    }
    try:
        res = await es.search(index="siem-logs-*", body=query)
    except Exception as exc:
        log.error("ES entity discovery failed: %s", exc)
        return []

    entities: list[tuple[str, str]] = []
    for b in res["aggregations"]["users"]["buckets"]:
        name = str(b["key"]).strip()
        if name and name not in ("", "null", "-"):
            entities.append((name, "user"))
    for b in res["aggregations"]["hosts"]["buckets"]:
        name = str(b["key"]).strip()
        if name and name not in ("", "null", "-"):
            entities.append((name, "machine"))

    log.info("UEBA — %d entités découvertes (%d users, %d machines)",
             len(entities),
             sum(1 for _, t in entities if t == "user"),
             sum(1 for _, t in entities if t == "machine"))
    return entities


# ── Persistance PG ────────────────────────────────────────────────────────────

async def _save_profile(
    pool,
    entity_id: str,
    entity_type: str,
    baseline_stats: dict,
    typical_hosts: list[str],
    typical_ips:   list[str],
    peak_hours:    list[int],
    risk_score:    int,
    anomaly_count: int,
    last_anomaly_at,
) -> None:
    from .ml_pipeline import _OFF_HOURS

    now          = datetime.now(timezone.utc)
    period_start = (now - timedelta(days=30)).date()
    period_end   = now.date()
    avg_events   = round(baseline_stats.get("login_count_per_day", {}).get("mean", 0.0), 2)
    avg_data_mb  = round(baseline_stats.get("data_volume_mb",      {}).get("mean", 0.0), 2)

    login_hours_json = json.dumps({
        "peak_hours": peak_hours,
        "off_hours":  sorted(_OFF_HOURS),
    })

    async with pool.acquire() as conn:
        prev = await conn.fetchval(
            "SELECT risk_score_current FROM ueba_profiles "
            "WHERE entity_id=$1 AND entity_type=$2::entity_type",
            entity_id, entity_type,
        )
        await conn.execute(
            "DELETE FROM ueba_profiles WHERE entity_id=$1 AND entity_type=$2::entity_type",
            entity_id, entity_type,
        )
        await conn.execute(
            """INSERT INTO ueba_profiles (
                entity_id, entity_type,
                profile_period_start, profile_period_end,
                typical_login_hours, typical_source_ips, typical_accessed_systems,
                avg_daily_events, avg_daily_data_mb,
                risk_score_current, risk_score_previous,
                anomaly_count_7d, last_anomaly_at, last_updated
            ) VALUES (
                $1, $2::entity_type,
                $3, $4,
                $5::jsonb, $6::jsonb, $7::jsonb,
                $8, $9,
                $10, $11,
                $12, $13, NOW()
            )""",
            entity_id, entity_type,
            period_start, period_end,
            login_hours_json,
            json.dumps(typical_ips),
            json.dumps(typical_hosts),
            avg_events, avg_data_mb,
            risk_score, prev if prev is not None else None,
            anomaly_count, last_anomaly_at,
        )


# ── Création d'alerte UEBA ────────────────────────────────────────────────────

async def _create_ueba_alert(
    pool,
    entity_id: str,
    entity_type: str,
    score: int,
    level: str,
    explanation: str,
) -> None:
    alert_id = str(uuid.uuid4())
    try:
        async with pool.acquire() as conn:
            rule_id = await conn.fetchval(
                "SELECT id FROM correlation_rules "
                "WHERE rule_type = 'behavioral' AND is_active = TRUE LIMIT 1"
            )
            if not rule_id:
                rule_id = await conn.fetchval(
                    """INSERT INTO correlation_rules (
                        name, rule_type, conditions, alert_level, confidence_score, is_active
                    ) VALUES (
                        'UEBA Behavioral Anomaly', 'behavioral',
                        '{"type": "ueba_anomaly"}'::jsonb,
                        'WARNING'::alert_level, 75, TRUE
                    )
                    ON CONFLICT (name) DO UPDATE SET is_active = TRUE
                    RETURNING id"""
                )
            affected_hosts = json.dumps([entity_id] if entity_type == "machine" else [])
            usernames      = json.dumps([entity_id] if entity_type == "user"    else [])
            await conn.execute(
                """INSERT INTO alerts (
                    id, rule_id, title, level, status,
                    correlated_event_ids, source_ips, affected_hosts, usernames,
                    mitre_tactic, confidence_score, notes
                ) VALUES (
                    $1::uuid, $2::uuid, $3, $4::alert_level, 'open'::alert_status,
                    '[]'::jsonb, '[]'::jsonb, $5::jsonb, $6::jsonb,
                    'TA0000', $7, $8
                )""",
                alert_id, str(rule_id),
                f"[UEBA] Anomalie comportementale — {entity_id} (score={score}/100)",
                level,
                affected_hosts, usernames,
                score,
                explanation[:500],
            )
        log.info("UEBA alerte créée : %s %s score=%d [%s]", entity_type, entity_id, score, level)
    except Exception as exc:
        log.error("UEBA alert creation error for %s: %s", entity_id, exc)


# ── Fallback heuristique (quand l'historique ML est insuffisant) ─────────────

_OFF_HOURS_HEURISTIC = set(range(0, 8)) | set(range(18, 24))
_PRIV_ACTIONS = ["privilege_escalation", "sudo", "root_login", "admin_access"]


async def _process_entity_heuristic(es, pool, entity_id: str, entity_type: str) -> bool:
    """
    Scoring heuristique basé sur 5 règles à seuils.
    Activé quand l'historique ML est < 7 jours.
    """
    filter_field = "username" if entity_type == "user" else "host"
    query: dict = {
        "size": 0,
        "query": {"bool": {"must": [
            {"term":  {filter_field: entity_id}},
            {"range": {"@timestamp": {"gte": "now-30d"}}},
        ]}},
        "aggs": {
            "login_failed": {"filter": {"terms": {"event_action": [
                "login_failed", "auth_failed", "login_failure", "authentication_failed",
            ]}}},
            "per_day": {"date_histogram": {"field": "@timestamp", "calendar_interval": "1d"}},
            "off_hours": {
                "filter": {
                    "script": {"script": {
                        "source": "int h=doc['@timestamp'].value.getHour(); return h<8||h>=18;",
                        "lang":   "painless",
                    }}
                }
            },
            "privileged": {"filter": {"terms": {"event_action": _PRIV_ACTIONS}}},
            "ips":   {"terms": {"field": "source_ip", "size": 20}},
            "hosts": {"terms": {"field": "host",      "size": 20}},
            "hours": {
                "terms": {
                    "script": {"source": "doc['@timestamp'].value.getHour()", "lang": "painless"},
                    "size": 24,
                }
            },
        },
    }

    try:
        resp = await es.search(index="siem-logs-*", body=query)
    except Exception as exc:
        log.error("ES heuristic error for %s %s: %s", entity_type, entity_id, exc)
        return False

    total = resp["hits"]["total"]["value"]
    if total < 3:
        return False

    aggs        = resp["aggregations"]
    days_b      = aggs["per_day"]["buckets"]
    active_days = max(sum(1 for d in days_b if d["doc_count"] > 0), 1)
    avg_daily   = total / active_days

    failed    = aggs["login_failed"]["doc_count"]
    off       = aggs["off_hours"]["doc_count"]
    priv      = aggs["privileged"]["doc_count"]
    off_pct   = off / max(total, 1)
    ips_list  = [b["key"] for b in aggs["ips"]["buckets"]   if b["doc_count"] >= 2]
    hosts_list= [b["key"] for b in aggs["hosts"]["buckets"] if b["doc_count"] >= 2]
    hours_raw = [int(b["key"]) for b in aggs["hours"]["buckets"] if b["doc_count"] >= 2]
    peak_hours= [h for h in hours_raw if h not in _OFF_HOURS_HEURISTIC]
    new_ips   = max(0, len(aggs["ips"]["buckets"]) - len(ips_list))

    # Scoring heuristique (5 règles)
    score = anomalies = 0
    if failed / active_days > 5:  score += 30; anomalies += 1  # noqa: E702
    if off_pct > 0.30:             score += 20; anomalies += 1  # noqa: E702
    if new_ips > 3:                score += 25; anomalies += 1  # noqa: E702
    if priv > 0:                   score += 40; anomalies += 1  # noqa: E702
    if avg_daily > 500:            score += 15; anomalies += 1  # noqa: E702
    score = min(score, 100)

    last_anomaly_at = datetime.now(timezone.utc) if score >= 50 else None
    baseline_stats  = {
        "login_count_per_day": {"mean": round(avg_daily, 2), "sufficient": True},
        "data_volume_mb":      {"mean": 0.0,                 "sufficient": False},
    }

    await _save_profile(
        pool, entity_id, entity_type,
        baseline_stats, hosts_list, ips_list, peak_hours,
        score, anomalies, last_anomaly_at,
    )
    if score >= 70:
        level = "CRITICAL" if score >= 90 else "HIGH" if score >= 75 else "WARNING"
        await _create_ueba_alert(
            pool, entity_id, entity_type, score, level,
            f"Anomalie comportementale (heuristique) — {entity_id} (score={score}/100)",
        )

    log.info("UEBA heuristique — %s %-20s score=%3d anomalies=%d", entity_type, entity_id, score, anomalies)
    return True


# ── Pipeline ML par entité ────────────────────────────────────────────────────

async def _process_entity(es, pool, entity_id: str, entity_type: str) -> bool:
    """
    Pipeline ML complet (IF + Z-Score).
    Bascule automatiquement sur l'heuristique si l'historique est < 7 jours.
    """
    from .ml_pipeline import (
        get_features_window, get_features_for_entity,
        compute_baseline_stats, compute_typical_hosts, compute_typical_ips, compute_peak_hours,
        train_isolation_forest, compute_if_score,
        compute_zscore_score, compute_final_score, build_explanation,
        _WINDOW_DAYS, _ALERT_THRESHOLD, _MIN_HISTORY_DAYS,
    )

    try:
        # ── Étape 1 : features historiques (30 jours) ─────────────────────────
        historical = await get_features_window(es, entity_id, entity_type, _WINDOW_DAYS)
        if len(historical) < _MIN_HISTORY_DAYS:
            log.info(
                "UEBA ML → heuristique pour %s %s (%d jours < %d requis)",
                entity_type, entity_id, len(historical), _MIN_HISTORY_DAYS,
            )
            return await _process_entity_heuristic(es, pool, entity_id, entity_type)

        # ── Étape 2 : baseline statistique ────────────────────────────────────
        baseline_stats = compute_baseline_stats(historical)
        typical_hosts  = compute_typical_hosts(historical)
        typical_ips    = compute_typical_ips(historical)
        peak_hours     = compute_peak_hours(historical)

        # ── Étape 3 : entraîner l'Isolation Forest ────────────────────────────
        model, scaler = train_isolation_forest(historical)

        # ── Étape 4 : features du jour courant ────────────────────────────────
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        today_features = await get_features_for_entity(es, entity_id, entity_type, today)

        # ── Étape 5 : scoring ─────────────────────────────────────────────────
        if today_features is not None:
            hosts_today = set(today_features["_meta"].get("hosts_today", []))
            today_features["new_system_access_count"] = len(hosts_today - set(typical_hosts))

            if_score                 = compute_if_score(model, scaler, today_features)
            zscore_score, anomalous  = compute_zscore_score(today_features, baseline_stats)
            final_score, level       = compute_final_score(if_score, zscore_score, anomalous)
            explanation              = build_explanation(anomalous, entity_id, final_score)
        else:
            final_score = 0
            level       = "NORMAL"
            anomalous   = []
            explanation = f"Activité insuffisante aujourd'hui pour {entity_id}"

        # ── Étape 6 : alerte si score ≥ seuil ────────────────────────────────
        last_anomaly_at = None
        if final_score >= _ALERT_THRESHOLD:
            last_anomaly_at = datetime.now(timezone.utc)
            await _create_ueba_alert(pool, entity_id, entity_type, final_score, level, explanation)

        # ── Étape 7 : persistance PG ──────────────────────────────────────────
        await _save_profile(
            pool, entity_id, entity_type,
            baseline_stats, typical_hosts, typical_ips, peak_hours,
            final_score, len(anomalous), last_anomaly_at,
        )

        log.info(
            "UEBA ML — %s %-20s  score=%3d [%-8s]  anomalies=%d  if=%.1f",
            entity_type, entity_id, final_score, level,
            len(anomalous), if_score if today_features else 0.0,
        )
        return True

    except Exception as exc:
        log.error("UEBA ML error for %s %s: %s", entity_type, entity_id, exc, exc_info=True)
        return False


# ── Point d'entrée principal ──────────────────────────────────────────────────

async def compute_profiles() -> dict:
    """
    Recalcule tous les profils UEBA avec le pipeline ML (IF + Z-Score).
    Appelé en background par POST /ueba/compute.
    """
    from app.core.elasticsearch import get_es_client

    log.info("UEBA ML — démarrage du cycle de calcul")
    es   = get_es_client()
    pool = await get_pg_pool()

    entities = await _discover_entities(es)
    if not entities:
        log.warning("UEBA ML — aucune entité trouvée dans ES")
        return {"users": 0, "machines": 0, "status": "no_data"}

    user_count = host_count = 0
    for entity_id, entity_type in entities:
        ok = await _process_entity(es, pool, entity_id, entity_type)
        if ok:
            if entity_type == "user":
                user_count += 1
            else:
                host_count += 1

    log.info("UEBA ML — cycle terminé : %d users, %d machines", user_count, host_count)
    return {"users": user_count, "machines": host_count, "status": "done"}
