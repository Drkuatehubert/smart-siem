"""
service.py — Lecture du journal d'audit depuis Elasticsearch
Responsable : Chef de Projet & Sécurité
Index : idx-audit-log (append-only)
"""

from typing import Optional
from app.core.elasticsearch import get_es_client


async def get_audit_logs(
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    page: int = 1,
    size: int = 50,
) -> dict:
    es = get_es_client()

    must_clauses = []

    if user_id:
        must_clauses.append({"term": {"user_id": user_id}})
    if action:
        must_clauses.append({"term": {"action": action}})
    if from_date or to_date:
        range_filter = {}
        if from_date:
            range_filter["gte"] = from_date
        if to_date:
            range_filter["lte"] = to_date
        must_clauses.append({"range": {"created_at": range_filter}})

    query = {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}

    result = await es.search(
        index="idx-audit-log",
        body={
            "query": query,
            "sort": [{"created_at": {"order": "desc"}}],
            "from": (page - 1) * size,
            "size": size,
        }
    )

    hits = result["hits"]["hits"]
    total = result["hits"]["total"]["value"]

    return {
        "total": total,
        "page": page,
        "size": size,
        "results": [
            {"id": h["_id"], **h["_source"]} for h in hits
        ]
    }
