from app.core.elasticsearch import get_es_client
async def list_sources(page=1, size=50):
    es = get_es_client()
    res = await es.search(index="idx-sources",body={"query":{"match_all":{}},"from":(page-1)*size,"size":size})
    return {"total":res["hits"]["total"]["value"],"page":page,"size":size,"results":[{"id":h["_id"],**h["_source"]} for h in res["hits"]["hits"]]}
async def create_source(data: dict):
    es = get_es_client()
    res = await es.index(index="idx-sources", document=data)
    return {"id": res["_id"], **data}
