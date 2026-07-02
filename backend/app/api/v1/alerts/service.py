from datetime import datetime, timezone
from typing import Optional

from app.core.elasticsearch import get_es_client

# Les alertes sont créées exclusivement par le moteur de corrélation (correlation_engine_2.py)
# qui écrit dans PostgreSQL et dans l'index alert-mirror.
# Le backend est en LECTURE SEULE pour la création d'alertes.

_ALERT_INDEX = "alert-mirror"


def _hit_to_alert(hit: dict) -> dict:
    src = hit["_source"]
    return {
        "id": hit["_id"],
        "pg_alert_id": src.get("pg_alert_id"),
        "level": src.get("level"),
        "status": src.get("status"),
        "title": src.get("title"),
        "rule_name": src.get("rule_name"),
        "mitre_tactic": src.get("mitre_tactic"),
        "source_ips": src.get("source_ips", []),
        "affected_hosts": src.get("affected_hosts", []),
        "confidence_score": src.get("confidence_score"),
        "triggered_at": src.get("@timestamp"),
    }


async def list_alerts(
    niveau=None, statut=None, page=1, size=50, org_scope=None
) -> dict:
    es = get_es_client()
    must = []
    if niveau:
        must.append({"term": {"level": niveau}})
    if statut:
        must.append({"term": {"status": statut}})
    q = {"bool": {"must": must}} if must else {"match_all": {}}
    res = await es.search(
        index=_ALERT_INDEX,
        body={
            "query": q,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "from": (page - 1) * size,
            "size": size,
        },
    )
    return {
        "total": res["hits"]["total"]["value"],
        "page": page,
        "size": size,
        "results": [_hit_to_alert(h) for h in res["hits"]["hits"]],
    }


async def get_alert(alert_id: str) -> Optional[dict]:
    """Récupère une alerte depuis alert-mirror par son pg_alert_id (UUID PostgreSQL)."""
    es = get_es_client()
    res = await es.search(
        index=_ALERT_INDEX,
        body={
            "query": {"term": {"pg_alert_id": alert_id}},
            "size": 1,
        },
    )
    hits = res["hits"]["hits"]
    if not hits:
        return None
    return _hit_to_alert(hits[0])


async def update_alert_status(
    alert_id: str,
    statut: str,
    assigned_to: Optional[str],
    commentaires: Optional[str],
) -> dict:
    """Met à jour le champ 'status' dans alert-mirror.
    alert-mirror a un mapping strict : seul 'status' peut être modifié.
    """
    es = get_es_client()
    # Chercher le document ES par pg_alert_id pour obtenir l'_id ES réel
    res = await es.search(
        index=_ALERT_INDEX,
        body={"query": {"term": {"pg_alert_id": alert_id}}, "size": 1},
    )
    hits = res["hits"]["hits"]
    if not hits:
        return {"id": alert_id, "status": statut, "error": "alerte introuvable"}
    es_id = hits[0]["_id"]
    await es.update(
        index=_ALERT_INDEX,
        id=es_id,
        body={"doc": {"status": statut}},
    )
    return {"id": alert_id, "es_id": es_id, "status": statut}


# ─── Supprimé : create_alert() ───────────────────────────────────────────────
# Les alertes sont générées par le moteur de corrélation (correlation_engine_2.py)
# via le pipeline : ES siem-logs-* → règles PG → alerte PG + alert-mirror.
# Le backend ne crée jamais d'alertes directement.
