"""
normalizer/main.py — Worker de normalisation (consomme Redis Streams → indexe dans ES)
Couche 3 : Normalisation & Enrichissement
"""
import asyncio
import json
import os
import logging
from datetime import datetime, timezone, timedelta

import redis.asyncio as aioredis
from elasticsearch import AsyncElasticsearch

from schema import build_normalized_doc
from parser_engine import parse_log
from tagger import tag_log
from enricher import enrich_log

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("normalizer")

REDIS_HOST  = os.getenv("REDIS_HOST", "redis")
REDIS_PORT  = int(os.getenv("REDIS_PORT", 6379))
STREAM_KEY  = os.getenv("REDIS_STREAM_KEY", "siem:logs:raw")
ES_HOST     = os.getenv("ELASTICSEARCH_HOST", "http://elasticsearch:9200")
ES_USER     = os.getenv("ELASTICSEARCH_USERNAME", "elastic")
ES_PASS     = os.getenv("ELASTICSEARCH_PASSWORD", "changeme")
RETENTION   = int(os.getenv("LOG_RETENTION_DAYS", 30))
CONSUMER_GROUP = "normalizer-group"
CONSUMER_NAME  = "normalizer-1"


async def main():
    r = aioredis.from_url(f"redis://{REDIS_HOST}:{REDIS_PORT}", decode_responses=True)
    es = AsyncElasticsearch(hosts=[ES_HOST], basic_auth=(ES_USER, ES_PASS), verify_certs=False)

    # Créer le consumer group si inexistant
    try:
        await r.xgroup_create(STREAM_KEY, CONSUMER_GROUP, id="0", mkstream=True)
    except Exception:
        pass  # Déjà créé

    logger.info("Normalizer démarré — en écoute sur %s", STREAM_KEY)

    while True:
        try:
            messages = await r.xreadgroup(
                CONSUMER_GROUP, CONSUMER_NAME, {STREAM_KEY: ">"}, count=10, block=1000
            )
            for stream, entries in (messages or []):
                for msg_id, data in entries:
                    try:
                        raw = json.loads(data.get("data", "{}"))
                        parsed   = parse_log(raw)
                        tagged   = tag_log(parsed)
                        enriched = enrich_log(tagged)
                        doc      = build_normalized_doc(enriched, retention_days=RETENTION)
                        await es.index(index="idx-logs", document=doc)
                        await r.xack(STREAM_KEY, CONSUMER_GROUP, msg_id)
                        logger.debug("Log indexé : %s", doc.get("host"))
                    except Exception as e:
                        logger.error("Erreur normalisation msg %s : %s", msg_id, e)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Erreur stream : %s", e)
            await asyncio.sleep(2)

    await r.aclose()
    await es.close()


if __name__ == "__main__":
    asyncio.run(main())
