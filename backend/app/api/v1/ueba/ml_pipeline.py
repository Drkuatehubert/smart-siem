"""
backend/app/api/v1/ueba/ml_pipeline.py
Pipeline ML UEBA — Isolation Forest (60%) + Z-Score (40%)
Porté depuis temp-data/ueba/ et adapté aux clients ES/PG du backend.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

log = logging.getLogger("ueba.ml")

# ── Constantes ────────────────────────────────────────────────────────────────

_ES_INDEX        = "siem-logs-*"
_WINDOW_DAYS     = 30      # jours d'historique pour la baseline et l'IF
_MIN_HISTORY_DAYS = 7      # minimum pour entraîner l'IF
_MIN_EVENTS_DAY  = 10      # minimum d'événements par jour pour extraire les features
_MIN_OCCURRENCES = 3       # minimum de jours pour qu'un host/IP soit "typique"
_ALERT_THRESHOLD = 70      # score >= seuil → alerte UEBA
_BIZ_START       = 8       # début heures ouvrées
_BIZ_END         = 18      # fin heures ouvrées
_OFF_HOURS       = set(range(0, _BIZ_START)) | set(range(_BIZ_END, 24))

IF_WEIGHT        = 0.6
ZSCORE_WEIGHT    = 0.4

# Ordre fixe imposé au vecteur de features (doit être stable entre entraînement et inférence)
FEATURE_NAMES = [
    "login_hour_mean",
    "login_count_per_day",
    "unique_source_ips",
    "unique_hosts_accessed",
    "failed_login_ratio",
    "data_volume_mb",
    "off_hours_activity_ratio",
    "new_system_access_count",
]

FEATURES_CONFIG: dict[str, dict] = {
    "login_hour_mean": {
        "weight": 0.13, "zscore_threshold": 2.5, "direction": "both",
        "desc": "Heure moyenne de connexion dans la journée (0–23)",
    },
    "login_count_per_day": {
        "weight": 0.12, "zscore_threshold": 3.0, "direction": "high",
        "desc": "Nombre de connexions réussies par jour",
    },
    "unique_source_ips": {
        "weight": 0.10, "zscore_threshold": 2.5, "direction": "high",
        "desc": "Nombre d'adresses IP sources distinctes par jour",
    },
    "unique_hosts_accessed": {
        "weight": 0.15, "zscore_threshold": 2.5, "direction": "high",
        "desc": "Nombre de machines/serveurs distincts accédés par jour",
    },
    "failed_login_ratio": {
        "weight": 0.10, "zscore_threshold": 3.0, "direction": "high",
        "desc": "Ratio échecs authentification / total tentatives (0–1)",
    },
    "data_volume_mb": {
        "weight": 0.20, "zscore_threshold": 3.0, "direction": "high",
        "desc": "Volume total de données transférées en Mo par jour",
    },
    "off_hours_activity_ratio": {
        "weight": 0.10, "zscore_threshold": 2.5, "direction": "high",
        "desc": "Ratio d'événements hors heures ouvrées (8h–18h) par jour",
    },
    "new_system_access_count": {
        "weight": 0.10, "zscore_threshold": 2.0, "direction": "high",
        "desc": "Nombre de systèmes jamais accédés auparavant par jour",
    },
}


# ── Feature Engineering ──────────────────────────────────────────────────────

def _to_vector(features: dict) -> np.ndarray:
    return np.array([float(features.get(f, 0.0)) for f in FEATURE_NAMES], dtype=float)


async def get_features_for_entity(
    es,
    entity_id: str,
    entity_type: str,
    day: datetime,
) -> Optional[dict]:
    """Extrait les 8 features comportementales pour une entité sur une journée."""
    day_start = day.replace(hour=0,  minute=0,  second=0,  microsecond=0)
    day_end   = day.replace(hour=23, minute=59, second=59, microsecond=999999)
    filter_field = "username" if entity_type == "user" else "host"

    query: dict = {
        "query": {
            "bool": {
                "must": [
                    {"term":  {filter_field: entity_id}},
                    {"range": {"@timestamp": {
                        "gte": day_start.isoformat(),
                        "lte": day_end.isoformat(),
                    }}},
                ]
            }
        },
        "aggs": {
            "login_success": {"filter": {"term": {"event_action": "login_success"}}},
            "login_failed":  {"filter": {"term": {"event_action": "login_failed"}}},
            "login_hours": {
                "filter": {"term": {"event_action": "login_success"}},
                "aggs": {
                    "by_hour": {
                        "date_histogram": {
                            "field":             "@timestamp",
                            "calendar_interval": "hour",
                            "format":            "HH",
                        }
                    }
                },
            },
            "unique_ips":   {"cardinality": {"field": "source_ip", "precision_threshold": 40}},
            "unique_hosts": {"cardinality": {"field": "host",      "precision_threshold": 100}},
            "data_mb":      {"sum": {"field": "enriched_data.bytes_sent_mb", "missing": 0.0}},
            "hosts_list":   {"terms": {"field": "host",      "size": 20}},
            "ips_list":     {"terms": {"field": "source_ip", "size": 20}},
        },
        "size": 0,
    }

    try:
        resp = await es.search(index=_ES_INDEX, body=query)
    except Exception as exc:
        log.debug("ES error for %s %s on %s: %s", entity_type, entity_id, day_start.date(), exc)
        return None

    aggs        = resp.get("aggregations", {})
    total       = resp["hits"]["total"]["value"]

    if total < _MIN_EVENTS_DAY:
        return None

    login_success = aggs["login_success"]["doc_count"]
    login_failed  = aggs["login_failed"]["doc_count"]
    unique_ips    = aggs["unique_ips"]["value"]
    unique_hosts  = aggs["unique_hosts"]["value"]
    data_mb       = aggs["data_mb"]["value"] or 0.0
    hosts_today   = {b["key"] for b in aggs["hosts_list"]["buckets"]}
    ips_today     = {b["key"] for b in aggs["ips_list"]["buckets"]}
    hour_buckets  = aggs["login_hours"]["by_hour"]["buckets"]

    # login_hour_mean : moyenne pondérée des heures de connexion
    if hour_buckets:
        total_h   = sum(b["doc_count"] for b in hour_buckets)
        weighted  = sum(int(b["key_as_string"]) * b["doc_count"] for b in hour_buckets)
        hour_mean = (weighted / total_h) if total_h > 0 else 12.0
    else:
        hour_mean = 12.0

    # failed_login_ratio
    total_auth     = login_success + login_failed
    failed_ratio   = (login_failed / total_auth) if total_auth > 0 else 0.0

    # off_hours_activity_ratio
    off_count      = sum(
        b["doc_count"] for b in hour_buckets
        if int(b["key_as_string"]) < _BIZ_START or int(b["key_as_string"]) >= _BIZ_END
    )
    off_ratio      = (off_count / total) if total > 0 else 0.0

    # Heures actives (pour peak_hours dans le profil)
    active_hours   = [int(b["key_as_string"]) for b in hour_buckets if b["doc_count"] >= 2]

    return {
        "login_hour_mean":          round(hour_mean, 2),
        "login_count_per_day":      login_success,
        "unique_source_ips":        unique_ips,
        "unique_hosts_accessed":    unique_hosts,
        "failed_login_ratio":       round(failed_ratio, 4),
        "data_volume_mb":           round(data_mb, 2),
        "off_hours_activity_ratio": round(off_ratio, 4),
        "new_system_access_count":  0,  # enrichi plus tard avec typical_hosts
        "_meta": {
            "date":         day_start.date().isoformat(),
            "total_events": total,
            "hosts_today":  list(hosts_today),
            "ips_today":    list(ips_today),
            "active_hours": active_hours,
        },
    }


async def get_features_window(
    es,
    entity_id: str,
    entity_type: str,
    window_days: int = _WINDOW_DAYS,
) -> list[dict]:
    """Extrait les features sur N jours en parallèle (max 8 requêtes simultanées)."""
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    sem   = asyncio.Semaphore(8)

    async def _get(offset: int) -> Optional[dict]:
        async with sem:
            return await get_features_for_entity(es, entity_id, entity_type, today + timedelta(days=offset))

    results = await asyncio.gather(*[_get(o) for o in range(-window_days, 0)])
    return [r for r in results if r is not None]


# ── Baseline ─────────────────────────────────────────────────────────────────

def compute_baseline_stats(features_list: list[dict]) -> dict:
    """Calcule mean/std/min/max/p25/p75 par feature sur la fenêtre historique."""
    stats: dict = {}
    for fname in FEATURE_NAMES:
        values = [f[fname] for f in features_list if fname in f and f[fname] is not None]
        if len(values) < 3:
            stats[fname] = {
                "mean": 0.0, "std": 1.0, "min": 0.0, "max": 0.0,
                "p25": 0.0, "p75": 0.0, "n_days": len(values), "sufficient": False,
            }
            continue
        arr = np.array(values, dtype=float)
        stats[fname] = {
            "mean":       float(np.mean(arr)),
            "std":        max(float(np.std(arr, ddof=1)), 0.01),  # ddof=1 (Bessel)
            "min":        float(np.min(arr)),
            "max":        float(np.max(arr)),
            "p25":        float(np.percentile(arr, 25)),
            "p75":        float(np.percentile(arr, 75)),
            "n_days":     len(values),
            "sufficient": True,
        }
    return stats


def compute_typical_hosts(features_list: list[dict]) -> list[str]:
    """Hôtes vus dans au moins _MIN_OCCURRENCES journées = 'typiques'."""
    counts: dict[str, int] = {}
    for f in features_list:
        for h in f.get("_meta", {}).get("hosts_today", []):
            counts[h] = counts.get(h, 0) + 1
    return [h for h, n in counts.items() if n >= _MIN_OCCURRENCES]


def compute_typical_ips(features_list: list[dict]) -> list[str]:
    """IPs vues dans au moins _MIN_OCCURRENCES journées = 'typiques'."""
    counts: dict[str, int] = {}
    for f in features_list:
        for ip in f.get("_meta", {}).get("ips_today", []):
            counts[ip] = counts.get(ip, 0) + 1
    return [ip for ip, n in counts.items() if n >= _MIN_OCCURRENCES]


def compute_peak_hours(features_list: list[dict]) -> list[int]:
    """Heures avec activité régulière (≥ _MIN_OCCURRENCES jours) pendant les heures ouvrées."""
    counts: dict[int, int] = {}
    for f in features_list:
        for h in f.get("_meta", {}).get("active_hours", []):
            counts[h] = counts.get(h, 0) + 1
    return sorted(h for h, n in counts.items() if n >= _MIN_OCCURRENCES and h not in _OFF_HOURS)


# ── Isolation Forest ──────────────────────────────────────────────────────────

def train_isolation_forest(features_list: list[dict]):
    """Entraîne un Isolation Forest sur l'historique de features."""
    if len(features_list) < _MIN_HISTORY_DAYS:
        return None, None
    X = np.array([
        _to_vector(f) for f in features_list
        if not any(np.isnan(v) for v in _to_vector(f))
    ])
    if X.shape[0] < _MIN_HISTORY_DAYS:
        return None, None
    scaler  = StandardScaler()
    X_sc    = scaler.fit_transform(X)
    model   = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
    model.fit(X_sc)
    return model, scaler


def compute_if_score(model, scaler, today: dict) -> float:
    """Score Isolation Forest 0–100 (100 = très anormal)."""
    if model is None or scaler is None:
        return 0.0
    x      = _to_vector(today).reshape(1, -1)
    x_sc   = scaler.transform(x)
    raw    = model.score_samples(x_sc)[0]
    return max(0.0, min(100.0, (-raw) * 200.0))


# ── Z-Score ───────────────────────────────────────────────────────────────────

def compute_zscore_score(
    today: dict,
    baseline: dict,
) -> tuple[float, list[dict]]:
    """Score Z-Score 0–100 et liste des features anormales avec explication."""
    anomalous: list[dict] = []
    weighted:  list[float] = []

    for fname in FEATURE_NAMES:
        cfg   = FEATURES_CONFIG[fname]
        stats = baseline.get(fname, {})
        if not stats.get("sufficient", False):
            continue

        val   = float(today.get(fname, 0.0))
        mean  = stats["mean"]
        std   = stats["std"]
        z     = abs(val - mean) / std
        z_sgn = (val - mean) / std
        thr   = cfg["zscore_threshold"]
        dir_  = cfg["direction"]

        is_anom = (
            (dir_ == "high" and z_sgn >  thr) or
            (dir_ == "low"  and z_sgn < -thr) or
            (dir_ == "both" and z     >  thr)
        )
        if not is_anom:
            continue

        feat_score = min(100.0, (z - thr) / 5.0 * 100.0)
        weighted.append(feat_score * cfg["weight"])
        anomalous.append({
            "feature":     fname,
            "description": cfg["desc"],
            "today_value": round(val, 3),
            "mean":        round(mean, 3),
            "z_score":     round(z, 2),
            "threshold":   thr,
            "explanation": (
                f"{cfg['desc']} : valeur={val:.2f} "
                f"(moyenne={mean:.2f}, z={z:.1f}σ — seuil={thr}σ)"
            ),
        })

    if weighted:
        max_possible = sum(FEATURES_CONFIG[f]["weight"] for f in FEATURE_NAMES) * 100
        zscore_score = min(100.0, sum(weighted) / max_possible * 100.0 * 3)
    else:
        zscore_score = 0.0

    return zscore_score, anomalous


# ── Score final ───────────────────────────────────────────────────────────────

def compute_final_score(
    if_score: float,
    zscore_score: float,
    anomalous: list[dict],
) -> tuple[int, str]:
    """Score final 0–100 et niveau d'alerte."""
    final = IF_WEIGHT * if_score + ZSCORE_WEIGHT * zscore_score

    # Amplification si plusieurs features anormales simultanément
    if len(anomalous) >= 3:
        final = min(100.0, final * 1.2)
    elif len(anomalous) >= 2:
        final = min(100.0, final * 1.1)

    score = int(round(final))

    if score >= 90:
        level = "CRITICAL"
    elif score >= 75:
        level = "HIGH"
    elif score >= _ALERT_THRESHOLD:
        level = "WARNING"
    else:
        level = "NORMAL"

    return score, level


def build_explanation(anomalous: list[dict], entity_id: str, score: int) -> str:
    if not anomalous:
        return f"Comportement normal pour {entity_id} (score={score})"
    parts = " | ".join(f["explanation"] for f in anomalous[:3])
    return (
        f"Anomalie comportementale détectée pour {entity_id} (score={score}/100). "
        f"Features anormales ({len(anomalous)}) : {parts}"
    )
