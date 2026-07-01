"""
service.py â€” Lecture et export du journal d'audit

Responsable : Chef de Projet & SÃ©curitÃ©
Index : idx-audit-log (append-only, ILM 7 ans)

Fonctions :
  * get_audit_logs          â€” recherche paginÃ©e avec filtres
  * get_failed_logins       â€” agrÃ¨ge les Ã©checs de connexion
  * export_audit_logs       â€” streaming CSV/JSONL (max 100k rows)
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
    must: List[Dict[str, Any]] = []
    if user_id:
        must.append({"term": {"user_id": user_id}})
    if action:
        must.append({"term": {"action": action}})
    if from_date or to_date:
        rng: Dict[str, str] = {}
        if from_date:
            rng["gte"] = from_date
        if to_date:
            rng["lte"] = to_date
        must.append({"range": {"created_at": rng}})
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
    size = max(1, min(size, 500))
    query = await _build_query(user_id, action, from_date, to_date)
    res = await es.search(
        index="idx-audit-log",
        query=query,
        sort=[{"created_at": {"order": "desc"}}],
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
    es = get_es_client()
    query = await _build_query(None, None, from_date, to_date)
    if fmt == "csv":
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
        yield b""
    else:
        raise ValueError(f"format inconnu : {fmt}")

    sort = [{"created_at": "asc"}, {"_id": "asc"}]
    pit = None
    rows = 0
    try:
        # Use point-in-time if available (ES 7.10+)
        pit = await es.open_point_in_time(index="idx-audit-log", keep_alive="2m")
        pit_id = pit["id"]
    except Exception:
        pit_id = None

    search_after: Optional[List[Any]] = None
    while rows < max_rows:
        body: Dict[str, Any] = {
            "size": min(1000, max_rows - rows),
            "query": query,
            "sort": sort,
        }
        if search_after:
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
        search_after = hits[-1].get("sort")
        if not search_after:
            break

    if pit_id:
        try:
            await es.close_point_in_time(body={"id": pit_id})
        except Exception:
            pass
