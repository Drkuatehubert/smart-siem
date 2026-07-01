"""
service.py — Lecture et export du journal d'audit

Responsable : Chef de Projet & Sécurité
Index : idx-audit-log (append-only, ILM 7 ans)

Fonctions :
  * get_audit_logs          — recherche paginée avec filtres
  * get_failed_logins       — agrège les échecs de connexion
  * export_audit_logs       — streaming CSV/JSONL (max 100k rows)
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, AsyncGenerator, Dict, List, Optional

from app.core.elasticsearch import get_es_client


async def _build_query(
    user_id: Optional[str],
    action: Optional[str],
    from_date: Optional[str],
    to_date: Optional[str],
) -> Dict[str, Any]:
    # Construit dynamiquement une requête Elasticsearch "bool/must" à partir des
    # filtres fournis : chaque filtre non vide ajoute une condition supplémentaire.
    must: List[Dict[str, Any]] = []
    if user_id:
        must.append({"term": {"user_id": user_id}})
    if action:
        must.append({"term": {"action": action}})
    if from_date or to_date:
        rng: Dict[str, str] = {}
        if from_date:
            rng["gte"] = from_date  # "greater than or equal" : borne basse de la période
        if to_date:
            rng["lte"] = to_date    # "less than or equal" : borne haute de la période
        must.append({"range": {"created_at": rng}})
    # Si aucun filtre n'est fourni, on renvoie une requête "tout" plutôt qu'un
    # bool/must vide (comportement équivalent mais plus explicite/lisible).
    return {"bool": {"must": must}} if must else {"match_all": {}}


async def get_audit_logs(
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    page: int = 1,
    size: int = 50,
) -> Dict[str, Any]:
    es = get_es_client()
    size = max(1, min(size, 500))  # borne anti-abus, comme pour les autres listes paginées
    query = await _build_query(user_id, action, from_date, to_date)
    res = await es.search(
        index="idx-audit-log",
        query=query,
        sort=[{"created_at": {"order": "desc"}}],  # événements les plus récents en premier
        from_=(page - 1) * size,
        size=size,
    )
    return {
        "total": res["hits"]["total"]["value"],
        "page": page,
        "size": size,
        "results": [
            {"id": h["_id"], **h["_source"]} for h in res["hits"]["hits"]
        ],
    }


async def get_failed_logins(
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    page: int = 1,
    size: int = 50,
) -> Dict[str, Any]:
    # Vue spécialisée : ne remonte que les tentatives de connexion échouées,
    # utile pour un tableau de bord de sécurité (repérer une attaque en cours).
    es = get_es_client()
    size = max(1, min(size, 500))
    must: List[Dict[str, Any]] = [{"term": {"action": "connexion_echouee"}}]
    if from_date or to_date:
        rng: Dict[str, str] = {}
        if from_date:
            rng["gte"] = from_date
        if to_date:
            rng["lte"] = to_date
        must.append({"range": {"created_at": rng}})
    res = await es.search(
        index="idx-audit-log",
        query={"bool": {"must": must}},
        sort=[{"created_at": {"order": "desc"}}],
        from_=(page - 1) * size,
        size=size,
    )
    return {
        "total": res["hits"]["total"]["value"],
        "from_date": from_date,
        "to_date": to_date,
        "results": [
            {"id": h["_id"], **h["_source"]} for h in res["hits"]["hits"]
        ],
    }


async def export_audit_logs(
    fmt: str,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    max_rows: int = 50_000,
) -> AsyncGenerator[bytes, None]:
    """
    Stream l'export (CSV ou JSONL) avec `search_after` (deep-paging safe).
    """
    # Cette fonction est un générateur asynchrone : elle produit les données au fur
    # et à mesure ("yield"), ce qui permet de streamer un export volumineux vers le
    # client sans avoir à tout charger en mémoire côté serveur.
    es = get_es_client()
    query = await _build_query(None, None, from_date, to_date)
    if fmt == "csv":
        # io.StringIO sert de "fichier CSV en mémoire" : on y écrit une ligne à la fois
        # puis on vide le buffer (truncate) après chaque envoi au client.
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "id", "created_at", "user_id", "action", "ip_address",
            "user_agent", "request_id", "http_method", "http_path",
            "status", "target_entity", "target_id", "details",
        ])
        yield buf.getvalue().encode("utf-8")
        buf.seek(0)
        buf.truncate(0)
    elif fmt == "jsonl":
        # JSON Lines : pas d'en-tête à écrire, chaque ligne est un objet JSON indépendant.
        yield b""
    else:
        raise ValueError(f"format inconnu : {fmt}")

    # Tri stable (created_at + _id) requis pour que `search_after` fonctionne correctement :
    # contrairement à la pagination par `from_`/`size`, `search_after` reste performant
    # même après des dizaines de milliers de résultats ("deep paging").
    sort = [{"created_at": "asc"}, {"_id": "asc"}]
    pit = None
    rows = 0
    try:
        # Point-in-time : fige une vue cohérente de l'index le temps de l'export,
        # pour éviter que des documents insérés entre-temps ne décalent la pagination.
        pit = await es.open_point_in_time(index="idx-audit-log", keep_alive="2m")
        pit_id = pit["id"]
    except Exception:
        # Elasticsearch trop ancien ou fonctionnalité indisponible : on continue sans PIT
        # (léger risque d'incohérence sur un export concurrent à de nouvelles écritures).
        pit_id = None

    search_after: Optional[List[Any]] = None
    while rows < max_rows:
        body: Dict[str, Any] = {
            "size": min(1000, max_rows - rows),  # récupère par lots de 1000 max
            "query": query,
            "sort": sort,
        }
        if search_after:
            # Reprend la pagination juste après le dernier document du lot précédent.
            body["search_after"] = search_after
        if pit_id:
            body["pit"] = {"id": pit_id, "keep_alive": "2m"}

        res = await es.search(body=body)
        hits = res["hits"]["hits"]
        if not hits:
            break
        for h in hits:
            src = h["_source"]
            if fmt == "csv":
                writer.writerow([
                    h["_id"], src.get("created_at"), src.get("user_id"),
                    src.get("action"), src.get("ip_address"), src.get("user_agent"),
                    src.get("request_id"), src.get("http_method"), src.get("http_path"),
                    src.get("status"), src.get("target_entity"), src.get("target_id"),
                    json.dumps(src.get("details", {}), ensure_ascii=False),
                ])
                yield buf.getvalue().encode("utf-8")
                buf.seek(0)
                buf.truncate(0)
            else:  # jsonl
                yield (json.dumps({"id": h["_id"], **src}, ensure_ascii=False) + "\n").encode("utf-8")
            rows += 1
            if rows >= max_rows:
                break
        # Le curseur de pagination pour le prochain lot = valeurs de tri du dernier hit reçu.
        search_after = hits[-1].get("sort")
        if not search_after:
            break

    if pit_id:
        try:
            # Libère la ressource "point-in-time" côté Elasticsearch dès que l'export est fini.
            await es.close_point_in_time(body={"id": pit_id})
        except Exception:
            pass
