from app.core.elasticsearch import get_es_client
async def list_rules(page=1, size=50):
    es = get_es_client()
    res = await es.search(index="idx-correlation-rules",body={"query":{"match_all":{}},"from":(page-1)*size,"size":size})
    return {"total":res["hits"]["total"]["value"],"page":page,"size":size,"results":[{"id":h["_id"],**h["_source"]} for h in res["hits"]["hits"]]}
async def create_rule(data: dict, user_id: str):
    es = get_es_client()
    doc = {**data, "created_by": user_id}
    res = await es.index(index="idx-correlation-rules", document=doc)
    return {"id": res["_id"], **doc}
async def delete_rule(rule_id: str):
    es = get_es_client()
    await es.delete(index="idx-correlation-rules", id=rule_id)
