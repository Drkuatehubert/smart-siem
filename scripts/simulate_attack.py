"""scripts/simulate_attack.py — Simulation brute-force SSH (déclenche alerte HIGH)"""
import asyncio, os, uuid
from datetime import datetime, timezone, timedelta
from elasticsearch import AsyncElasticsearch

ES_HOST=os.getenv("ELASTICSEARCH_HOST","http://elasticsearch:9200")
ES_USER=os.getenv("ELASTICSEARCH_USERNAME","elastic"); ES_PASS=os.getenv("ELASTICSEARCH_PASSWORD","changeme")

async def main():
    es=AsyncElasticsearch(hosts=[ES_HOST],basic_auth=(ES_USER,ES_PASS),verify_certs=False)
    now=datetime.now(timezone.utc)
    print("Simulation brute-force SSH (10 tentatives en 20 secondes)...")
    for i in range(10):
        doc={"source_id":"simulation","timestamp":(now-timedelta(seconds=20-i*2)).isoformat(),"host":"srv-ssh-01","source_ip":"10.0.0.99","log_type":"auth","severity":"warning","raw_message":f"Failed password for root from 10.0.0.99 port {5000+i} ssh2","normalized_fields":{"username":"root","process":"sshd","message":"Failed password"},"tags":["auth","warning"],"is_flagged":False,"archived":False,"retention_expiry":(now+timedelta(days=30)).isoformat()}
        await es.index(index="idx-logs",document=doc)
    print("? 10 logs d attaque insérés ? le moteur de corrélation déclenchera une alerte HIGH")
    await es.close()
if __name__=="__main__": asyncio.run(main())
