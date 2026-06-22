from app.core.elasticsearch import get_es_client
async def get_summary():
    es = get_es_client()
    res = await es.search(index="idx-alerts", body={"query":{"term":{"statut":"ouvert"}},"aggs":{"by_level":{"terms":{"field":"niveau"}}},"size":0})
    buckets = res["aggregations"]["by_level"]["buckets"]
    return {"total_logs_24h": 0,"total_alerts_open": res["hits"]["total"]["value"],
            "alerts_by_level":[{"niveau":b["key"],"count":b["doc_count"]} for b in buckets],"log_volume_by_hour":[]}
