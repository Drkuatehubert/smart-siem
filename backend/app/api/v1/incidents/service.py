from app.core.elasticsearch import get_es_client
from datetime import datetime, timezone
async def list_incidents(page=1, size=50):
    es = get_es_client()
    res = await es.search(index="idx-incidents", body={"query":{"match_all":{}},"sort":[{"created_at":{"order":"desc"}}],"from":(page-1)*size,"size":size})
    return {"total":res["hits"]["total"]["value"],"page":page,"size":size,"results":[{"id":h["_id"],**h["_source"]} for h in res["hits"]["hits"]]}
async def create_incident(data: dict, owner_id: str):
    es = get_es_client()
    now = datetime.now(timezone.utc).isoformat()
    doc = {**data, "owner": owner_id, "created_at": now, "updated_at": now}
    res = await es.index(index="idx-incidents", document=doc)
    return {"id": res["_id"], **doc}
