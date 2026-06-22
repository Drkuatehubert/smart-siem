"""scripts/seed_users.py — Création des utilisateurs par défaut"""
import asyncio, os, bcrypt
from elasticsearch import AsyncElasticsearch
from datetime import datetime, timezone

ES_HOST=os.getenv("ELASTICSEARCH_HOST","http://elasticsearch:9200")
ES_USER=os.getenv("ELASTICSEARCH_USERNAME","elastic"); ES_PASS=os.getenv("ELASTICSEARCH_PASSWORD","changeme")

USERS=[
    {"username":"admin","email":"admin@siem.local","password":"Admin@2024!","role_id":"administrateur","org_scope":None},
    {"username":"analyste01","email":"analyste@siem.local","password":"Analyste@2024!","role_id":"analyste","org_scope":"filiale-a"},
    {"username":"lecteur01","email":"lecteur@siem.local","password":"Lecteur@2024!","role_id":"lecteur","org_scope":"filiale-a"},
]
async def main():
    es=AsyncElasticsearch(hosts=[ES_HOST],basic_auth=(ES_USER,ES_PASS),verify_certs=False)
    for u in USERS:
        existing=await es.search(index="idx-users",body={"query":{"term":{"username":u["username"]}},"size":1})
        if existing["hits"]["hits"]: print(f"  ? Existant: {u['username']}"); continue
        doc={**{k:v for k,v in u.items() if k!="password"},"password_hash":bcrypt.hashpw(u["password"].encode(),bcrypt.gensalt(12)).decode(),"is_active":True,"created_at":datetime.now(timezone.utc).isoformat()}
        await es.index(index="idx-users",document=doc); print(f"  ? Créé: {u['username']}")
    await es.close()
if __name__=="__main__": asyncio.run(main())
