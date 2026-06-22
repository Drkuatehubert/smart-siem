from app.core.elasticsearch import get_es_client
from app.core.security import hash_password
from datetime import datetime, timezone
async def list_users(page=1,size=50):
    es=get_es_client()
    res=await es.search(index="idx-users",body={"query":{"match_all":{}},"from":(page-1)*size,"size":size,"_source":{"excludes":["password_hash"]}})
    return {"total":res["hits"]["total"]["value"],"page":page,"size":size,"results":[{"id":h["_id"],**h["_source"]} for h in res["hits"]["hits"]]}
async def create_user(data:dict):
    es=get_es_client()
    doc={**data,"password_hash":hash_password(data.pop("password")),"is_active":True,"created_at":datetime.now(timezone.utc).isoformat()}
    res=await es.index(index="idx-users",document=doc)
    doc.pop("password_hash"); return {"id":res["_id"],**doc}
