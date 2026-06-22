"""scripts/seed_data.py — Génération de 1000+ logs simulés (Faker)"""
import asyncio, random, uuid, os
from datetime import datetime, timezone, timedelta
from elasticsearch import AsyncElasticsearch

ES_HOST=os.getenv("ELASTICSEARCH_HOST","http://elasticsearch:9200")
ES_USER=os.getenv("ELASTICSEARCH_USERNAME","elastic"); ES_PASS=os.getenv("ELASTICSEARCH_PASSWORD","changeme")

HOSTS=["srv-web-01","srv-db-01","srv-ad-01","fw-01","pc-user-01"]
TYPES=["auth","reseau","systeme","application"]
LEVELS=["info","info","info","warning","warning","critical"]
MESSAGES=["Failed password for root from 192.168.1.100","Accepted publickey for admin","Connection closed by 10.0.0.5","sudo: user=root","iptables: BLOCKED src=192.168.1.50","Apache: GET /admin HTTP/1.1 403"]

async def main():
    es=AsyncElasticsearch(hosts=[ES_HOST],basic_auth=(ES_USER,ES_PASS),verify_certs=False)
    now=datetime.now(timezone.utc)
    docs=[{"source_id":"seed","timestamp":(now-timedelta(minutes=random.randint(0,10080))).isoformat(),"host":random.choice(HOSTS),"source_ip":f"192.168.{random.randint(1,10)}.{random.randint(1,254)}","log_type":random.choice(TYPES),"severity":random.choice(LEVELS),"raw_message":random.choice(MESSAGES),"normalized_fields":{},"tags":[],"is_flagged":False,"archived":False,"retention_expiry":(now+timedelta(days=30)).isoformat()} for _ in range(1000)]
    for doc in docs: await es.index(index="idx-logs",document=doc)
    print(f"? {len(docs)} logs simulés insérés.")
    await es.close()
if __name__=="__main__": asyncio.run(main())
