"""alerts/service.py — Gestion des alertes dans ES"""
from datetime import datetime, timezone
from typing import Optional
from app.core.elasticsearch import get_es_client


async def list_alerts(niveau=None, statut=None, page=1, size=50, org_scope=None) -> dict:
    es = get_es_client()
    must = []
    if niveau: must.append({"term": {"niveau": niveau}})
    if statut: must.append({"term": {"statut": statut}})
    if org_scope: must.append({"term": {"org_scope": org_scope}})
    q = {"bool": {"must": must}} if must else {"match_all": {}}
    res = await es.search(index="idx-alerts", body={
        "query": q, "sort": [{"created_at": {"order": "desc"}}],
        "from": (page-1)*size, "size": size
    })
    return {"total": res["hits"]["total"]["value"], "page": page, "size": size,
            "results": [{"id": h["_id"], **h["_source"]} for h in res["hits"]["hits"]]}


async def update_alert_status(alert_id: str, statut: str, assigned_to: Optional[str], commentaires: Optional[str]) -> dict:
    es = get_es_client()
    doc = {"statut": statut, "updated_at": datetime.now(timezone.utc).isoformat()}
    if assigned_to: doc["assigned_to"] = assigned_to
    if commentaires: doc["commentaires"] = commentaires
    await es.update(index="idx-alerts", id=alert_id, body={"doc": doc})
    return {"id": alert_id, **doc}
