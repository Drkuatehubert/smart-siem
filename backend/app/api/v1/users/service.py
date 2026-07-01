"""
service.py — Logique métier de gestion des utilisateurs (durcie)

Responsable : Chef de Projet & Sécurité
Exigences : RF-SEC-02, RF-SEC-04

Fonctions exposées :
  * list_users          — pagination (capée)
  * get_user_by_id      — fetch unique
  * create_user         — unicité username + hachage + insertion
  * update_user         — patch partiel (last-admin guard)
  * delete_user         — delete (last-admin guard)
  * set_user_active     — active/désactive (utilisé par SOAR disable_account)
  * count_active_admins — utilisé par last-admin guard et dashboard
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status

from app.config import settings
from app.core.elasticsearch import get_es_client
from app.core.security import hash_password, verify_password
from app.core.rbac import Role

IDX = "idx-users"  # index Elasticsearch où sont stockés les documents utilisateur

# Champs sensibles — JAMAIS retournés en sortie.
_SENSITIVE = {"password_hash", "password_history", "mfa_pending_secret"}


def _sanitize(doc: Dict[str, Any]) -> Dict[str, Any]:
    # Retire systématiquement les champs sensibles d'un document avant de le renvoyer
    # à l'appelant, quel que soit le point d'entrée (liste, détail, création, update).
    for k in _SENSITIVE:
        doc.pop(k, None)
    return doc


# ─────────────────────────────────────────────────────────────────────────────
# Lecture
# ─────────────────────────────────────────────────────────────────────────────

async def list_users(page: int = 1, size: int = 50) -> Dict[str, Any]:
    """Liste paginée des utilisateurs. `size` bornée à 500."""
    # Empêche un appelant de demander une page de taille arbitrairement grande
    # (ex: size=1000000), qui surchargerait Elasticsearch et le réseau.
    size = max(1, min(size, 500))
    es = get_es_client()
    res = await es.search(
        index=IDX,
        query={"match_all": {}},
        from_=(page - 1) * size,   # pagination classique "offset" (page 1 => from_=0)
        size=size,
        _source={"excludes": list(_SENSITIVE)},  # exclut les champs sensibles dès la requête ES (défense en profondeur)
        sort=[{"created_at": {"order": "desc"}}],  # les plus récents en premier
    )
    return {
        "total": res["hits"]["total"]["value"],
        "page": page,
        "size": size,
        "results": [
            {"id": h["_id"], **_sanitize(dict(h["_source"]))} for h in res["hits"]["hits"]
        ],
    }


async def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    es = get_es_client()
    try:
        doc = await es.get(index=IDX, id=user_id)
        return {"id": doc["_id"], **_sanitize(dict(doc["_source"]))}
    except Exception:
        # Document introuvable (ou erreur ES) : on renvoie None, à l'appelant de
        # décider s'il s'agit d'un 404.
        return None


async def count_active_admins() -> int:
    # Utilisé pour empêcher de se retrouver sans aucun administrateur actif
    # (voir garde "last admin" dans update_user/delete_user ci-dessous).
    es = get_es_client()
    res = await es.count(
        index=IDX,
        query={
            "bool": {
                "must": [
                    {"term": {"role_id": Role.ADMINISTRATEUR}},
                    {"term": {"is_active": True}},
                ]
            }
        },
    )
    return res["count"]


# ─────────────────────────────────────────────────────────────────────────────
# Écriture
# ─────────────────────────────────────────────────────────────────────────────

async def create_user(data: Dict[str, Any]) -> Dict[str, Any]:
    es = get_es_client()
    username = data["username"].lower()

    # Unicité username : on utilise directement le username en minuscules comme
    # identifiant du document ES, ce qui rend la vérification d'unicité triviale
    # (un simple "exists" par id, sans recherche).
    exists = await es.exists(index=IDX, id=username)
    if exists:
        raise HTTPException(status_code=409, detail="Nom d'utilisateur déjà pris")

    raw_password = data.pop("password")
    doc: Dict[str, Any] = {
        **data,
        "username": username,
        "password_hash": hash_password(raw_password),  # jamais le mot de passe en clair n'est stocké
        "is_active": data.get("is_active", True),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_login_at": None,
        "locked_until": None,
        "must_reset_password": False,
        "password_history": [],
    }
    # refresh="wait_for" : attend que le document soit indexé et immédiatement
    # visible en recherche avant de renvoyer la réponse (évite qu'un GET juste
    # après la création ne renvoie 404 par effet de latence d'indexation).
    res = await es.index(index=IDX, id=username, document=doc, refresh="wait_for")
    return {"id": res["_id"], **_sanitize(doc)}


async def update_user(user_id: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    es = get_es_client()
    # On ne garde que les champs explicitement fournis (non None) : un PATCH partiel
    # ne doit jamais écraser un champ existant avec None par accident.
    patch = {k: v for k, v in patch.items() if v is not None}

    # Garde "last admin" si on touche au rôle admin ou à is_active :
    # empêche de rétrograder ou désactiver le dernier administrateur actif du système,
    # ce qui rendrait l'application impossible à administrer.
    if "role_id" in patch or "is_active" in patch:
        current = await get_user_by_id(user_id)
        if not current:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable")
        was_admin_active = (current.get("role_id") == Role.ADMINISTRATEUR and current.get("is_active", True))
        will_be_admin_active = (
            patch.get("role_id", current.get("role_id")) == Role.ADMINISTRATEUR
            and patch.get("is_active", current.get("is_active", True))
        )
        if was_admin_active and not will_be_admin_active:
            count = await count_active_admins()
            if count <= 1:
                raise HTTPException(
                    status_code=409,
                    detail="Impossible de retirer le dernier administrateur actif",
                )

    if not patch:
        # Rien à mettre à jour : on renvoie simplement l'état actuel.
        return await get_user_by_id(user_id)  # type: ignore[return-value]

    await es.update(index=IDX, id=user_id, doc=patch, refresh="wait_for")
    return await get_user_by_id(user_id)  # type: ignore[return-value]


async def delete_user(user_id: str) -> None:
    es = get_es_client()
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    # Même garde "last admin" que pour update_user, appliquée à la suppression.
    if user.get("role_id") == Role.ADMINISTRATEUR and user.get("is_active", True):
        count = await count_active_admins()
        if count <= 1:
            raise HTTPException(
                status_code=409,
                detail="Impossible de supprimer le dernier administrateur actif",
            )
    await es.delete(index=IDX, id=user_id, refresh="wait_for")


async def set_user_active(user_id: str, is_active: bool) -> Dict[str, Any]:
    # Simple raccourci au-dessus d'update_user, réutilisé notamment par le SOAR
    # pour désactiver automatiquement un compte compromis (action "disable_account").
    return await update_user(user_id, {"is_active": is_active})
