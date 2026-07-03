"""
exceptions.py — Gestionnaires d'erreurs HTTP personnalisés (durcis)

Responsable : Chef de Projet & Sécurité
Exigences : NFR-SEC-05 (pas de fuite d'info dans les erreurs)

Règles appliquées :
  * aucune query string n'est jamais renvoyée au client (fuite de tokens, API keys) ;
  * aucun champ `input` Pydantic (fuite de mots de passe saisis) ;
  * aucun traceback côté client sur 500 (loggué serveur uniquement) ;
  * chaque réponse inclut le `request_id` pour la traçabilité.
"""

from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger("errors")


def _safe_payload(request: Request, status_code: int, detail: str, extra: dict | None = None) -> dict:
    """Construit une réponse d'erreur normalisée."""
    # Toutes les réponses d'erreur de l'API suivent ce même format, ce qui facilite
    # leur traitement côté frontend (structure prévisible quel que soit le type d'erreur).
    payload = {
        "error": True,
        "status_code": status_code,
        "detail": detail,
        "path": request.url.path,  # PAS request.url (pas de query string, qui pourrait contenir un token en clair)
        "request_id": getattr(request.state, "request_id", None),
    }
    if extra:
        payload.update(extra)
    return payload


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    # Convertit toute HTTPException levée volontairement dans le code (401, 403, 404...)
    # en réponse JSON au format normalisé, tout en conservant le status_code et les headers d'origine.
    return JSONResponse(
        status_code=exc.status_code,
        content=_safe_payload(request, exc.status_code, str(exc.detail)),
        headers=getattr(exc, "headers", None),
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError,
) -> JSONResponse:
    """Ne renvoie que les erreurs sanitisées (loc/msg/type), pas le `input` (mots de passe)."""
    # Par défaut, Pydantic/FastAPI incluent la valeur saisie ("input") dans le détail
    # de l'erreur de validation : on la retire volontairement pour ne jamais renvoyer
    # au client un mot de passe ou une donnée sensible qu'il vient lui-même de saisir.
    sanitized = [
        {"loc": list(e.get("loc", [])), "msg": e.get("msg"), "type": e.get("type")}
        for e in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=_safe_payload(
            request, 422, "Données de requête invalides", {"errors": sanitized},
        ),
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """500 : log serveur complet, message client générique."""
    # `logger.exception` inclut automatiquement la stack trace complète dans les logs serveur,
    # ce qui permet de déboguer sans jamais exposer cette information à un client externe.
    logger.exception(
        "Unhandled exception on %s %s (request_id=%s): %s",
        request.method, request.url.path,
        getattr(request.state, "request_id", None),
        exc,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=_safe_payload(request, 500, "Erreur interne du serveur"),
    )
