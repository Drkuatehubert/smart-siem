from datetime import datetime, timedelta, timezone

from app.core.elasticsearch import get_es_client

_LOGS_INDEX   = "siem-logs-*"
_ALERTS_INDEX = "alert-mirror"


async def get_summary() -> dict:
    es = get_es_client()
    since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    # Nombre de logs des 24 dernières heures
    logs_res = await es.count(
        index=_LOGS_INDEX,
        body={"query": {"range": {"@timestamp": {"gte": since_24h}}}},
    )

    # Alertes ouvertes + répartition par niveau (champ 'level' dans alert-mirror)
    alerts_res = await es.search(
        index=_ALERTS_INDEX,
        body={
            "query": {"term": {"status": "open"}},
            "aggs": {"by_level": {"terms": {"field": "level", "size": 10}}},
            "size": 0,
        },
    )

    # Alertes CRITICAL ouvertes
    critical_res = await es.count(
        index=_ALERTS_INDEX,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"term": {"status": "open"}},
                        {"term": {"level": "CRITICAL"}},
                    ]
                }
            }
        },
    )

    # Volume horaire sur 24h
    volume_res = await es.search(
        index=_LOGS_INDEX,
        body={
            "query": {"range": {"@timestamp": {"gte": since_24h}}},
            "aggs": {
                "by_hour": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "hour",
                    }
                }
            },
            "size": 0,
        },
    )

    buckets      = alerts_res["aggregations"]["by_level"]["buckets"]
    hour_buckets = volume_res["aggregations"]["by_hour"]["buckets"]

    return {
        "total_logs_24h":    logs_res["count"],
        "total_alerts_open": alerts_res["hits"]["total"]["value"],
        "critical_alerts":   critical_res["count"],
        "alerts_by_level": [
            {"niveau": b["key"], "count": b["doc_count"]} for b in buckets
        ],
        "log_volume_by_hour": [
            {"hour": b["key_as_string"], "count": b["doc_count"]}
            for b in hour_buckets
        ],
    }
