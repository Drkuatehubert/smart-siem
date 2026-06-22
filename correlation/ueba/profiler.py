"""ueba/profiler.py — Calcul profil comportemental (7j glissants)"""
from datetime import datetime, timezone, timedelta
async def compute_profile(es, entity_id: str, entity_type: str = "user"):
    now = datetime.now(timezone.utc); since = (now - timedelta(days=7)).isoformat()
    res = await es.search(index="idx-logs",body={"query":{"bool":{"must":[{"range":{"timestamp":{"gte":since}}},{"term":{"normalized_fields.username":entity_id}}]}},"aggs":{"hourly":{"date_histogram":{"field":"timestamp","calendar_interval":"hour"}}},"size":0})
    buckets = res["aggregations"]["hourly"]["buckets"]
    hours = [b["key_as_string"][:13].split("T")[1][:2] for b in buckets if b["doc_count"]>0]
    avg_volume = sum(b["doc_count"] for b in buckets)/max(len(buckets),1)
    profile = {"entity_id":entity_id,"entity_type":entity_type,"typical_hours":list(set(hours)),"avg_volume_per_hour":avg_volume,"updated_at":now.isoformat()}
    await es.index(index="idx-ueba-profiles",id=entity_id,document=profile)
    return profile
