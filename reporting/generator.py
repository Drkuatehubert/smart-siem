"""reporting/generator.py — Orchestrateur de génération de rapports"""
import asyncio, os
from datetime import datetime, timezone
from elasticsearch import AsyncElasticsearch

ES_HOST=os.getenv("ELASTICSEARCH_HOST","http://elasticsearch:9200")

async def generate_report(type="weekly", from_date=None, to_date=None, format="pdf"):
    # TODO: implémenter avec WeasyPrint/openpyxl
    return {"id": f"report-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}", "status": "generated", "type": type}
