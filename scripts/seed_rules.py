"""scripts/seed_rules.py — Import des 6 règles MITRE dans ES"""
import asyncio, os, yaml, glob
from elasticsearch import AsyncElasticsearch

ES_HOST=os.getenv("ELASTICSEARCH_HOST","http://elasticsearch:9200")
ES_USER=os.getenv("ELASTICSEARCH_USERNAME","elastic"); ES_PASS=os.getenv("ELASTICSEARCH_PASSWORD","changeme")

async def main():
    es=AsyncElasticsearch(hosts=[ES_HOST],basic_auth=(ES_USER,ES_PASS),verify_certs=False)
    rule_files=glob.glob("correlation/rules/*.yaml")
    for f in rule_files:
        with open(f) as fp: rule=yaml.safe_load(fp)
        rule_id=rule.pop("id",None)
        if rule_id:
            await es.index(index="idx-correlation-rules",id=rule_id,document=rule)
            print(f"  ? Règle importée: {rule.get('nom')}")
    await es.close(); print(f"\n{len(rule_files)} règles importées.")
if __name__=="__main__": asyncio.run(main())
