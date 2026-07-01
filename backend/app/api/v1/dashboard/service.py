from app.core.elasticsearch import get_es_client
async def get_summary():
    # Une seule requête Elasticsearch : compte les alertes ouvertes (statut="ouvert")
    # et les regroupe par niveau de sévérité via une agrégation "terms".
    es = get_es_client()
    res = await es.search(index="idx-alerts", body={"query":{"term":{"statut":"ouvert"}},"aggs":{"by_level":{"terms":{"field":"niveau"}}},"size":0})
    # size=0 : on ne veut pas les documents eux-mêmes, seulement le total et les agrégations.
    buckets = res["aggregations"]["by_level"]["buckets"]
    return {"total_logs_24h": 0,"total_alerts_open": res["hits"]["total"]["value"],
            # NOTE : total_logs_24h et log_volume_by_hour sont encore à implémenter
            # (nécessitent une requête distincte sur l'index des logs bruts).
            "alerts_by_level":[{"niveau":b["key"],"count":b["doc_count"]} for b in buckets],"log_volume_by_hour":[]}
