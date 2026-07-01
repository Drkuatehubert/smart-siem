"""
logs/services.py
Toutes les interactions avec siem-logs-* dans Elasticsearch.
Aucune RLS ici (ES n'a pas de RLS natif) →
La vérification RBAC est faite dans le controller avant d'appeler le service.
"""
from app.core.elasticsearch import get_es_client, ES_INDEX_PATTERN
from datetime import datetime
from typing import Optional


async def search_logs(
    source_ip:    Optional[str]      = None,
    dest_ip:      Optional[str]      = None,
    event_action: Optional[str]      = None,
    log_type:     Optional[str]      = None,
    severity:     Optional[str]      = None,
    mitre_tactic: Optional[str]      = None,
    hostname:     Optional[str]      = None,
    username:     Optional[str]      = None,
    from_date:    Optional[datetime] = None,
    to_date:      Optional[datetime] = None,
    page:         int = 1,
    page_size:    int = 50,
) -> dict:
    """
    Construction dynamique de la query ES.
    Chaque filtre est optionnel : s'il est absent → non ajouté à la query.
    """
    must   = []
    filter_ = []

    # Filtres textuels (match exact sur keyword fields)
    _add_term(filter_, "source_ip",     source_ip)
    _add_term(filter_, "dest_ip",       dest_ip)
    _add_term(filter_, "event.action",  event_action)
    _add_term(filter_, "log_type",      log_type)
    _add_term(filter_, "severity",      severity)
    _add_term(filter_, "mitre_tactic",  mitre_tactic)
    _add_term(filter_, "host.name",     hostname)
    _add_term(filter_, "user.name",     username)

    # Filtre temporel
    if from_date or to_date:
        range_filter = {}
        if from_date: range_filter["gte"] = from_date.isoformat()
        if to_date:   range_filter["lte"] = to_date.isoformat()
        filter_.append({"range": {"@timestamp": range_filter}})

    query = {"bool": {"must": must, "filter": filter_}} if (must or filter_) else {"match_all": {}}

    es     = get_es_client()
    offset = (page - 1) * page_size
    result = await es.search(
        index=ES_INDEX_PATTERN,
        query=query,
        size=page_size,
        from_=offset,
        sort=[{"@timestamp": {"order": "desc"}}],
        track_total_hits=True
    )

    hits  = result["hits"]
    items = [h["_source"] | {"_id": h["_id"]} for h in hits["hits"]]
    total = hits["total"]["value"]

    return {"total": total, "page": page, "items": items}


async def get_log_by_id(log_id: str) -> dict | None:
    """Récupère un log ES précis par son _id."""
    es = get_es_client()
    try:
        result = await es.get(index=ES_INDEX_PATTERN, id=log_id)
        return result["_source"] | {"_id": result["_id"]}
    except Exception:
        return None


async def get_logs_by_ids(ids: list[str]) -> list[dict]:
    """Utilisé par alerts/services.py pour récupérer les logs d'une alerte."""
    if not ids:
        return []
    es = get_es_client()
    result = await es.search(
        index=ES_INDEX_PATTERN,
        query={"ids": {"values": ids}},
        size=len(ids)
    )
    return [h["_source"] | {"_id": h["_id"]} for h in result["hits"]["hits"]]


def _add_term(filter_list: list, field: str, value):
    """Ajoute un filtre terme uniquement si la valeur est présente."""
    if value:
        filter_list.append({"term": {field: value}})