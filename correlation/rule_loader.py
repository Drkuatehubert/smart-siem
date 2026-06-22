"""rule_loader.py — Chargement des règles depuis idx-correlation-rules"""
async def load_rules(es) -> list:
    res = await es.search(index="idx-correlation-rules", body={"query":{"term":{"active":True}},"size":100})
    return [{"id":h["_id"],**h["_source"]} for h in res["hits"]["hits"]]
