"""
exceptions.py â€” Gestionnaires d'erreurs HTTP personnalisÃ©s (durcis)

Responsable : Chef de Projet & SÃ©curitÃ©
Exigences : NFR-SEC-05 (pas de fuite d'info dans les erreurs)

RÃ¨gles appliquÃ©es :
  * aucune query string n'est jamais renvoyÃ©e au client (fuite de tokens, API keys) ;
  * aucun champ `input` Pydantic (fuite de mots de passe saisis) ;
  * aucun traceback cÃ´tÃ© client sur 500 (logguÃ© serveur uniquement) ;
  * chaque rÃ©ponse inclut le `request_id` pour la traÃ§abilitÃ©.
"""

from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

logger = logging.getLogger("errors")


def _safe_payload(request: Request, status_code: int, detail: str, extra: dict | None = None) -> dict:
    """Construit une rÃ©ponse d'erreur normalisÃ©e."""
    payload = {
        "error": True,
        "status_code": status_code,
        "detail": detail,
        "path": request.url.path,  # PAS request.url (pas de query string)
        "request_id": getattr(request.state, "request_id", None),
    }
    if extra:
        payload.update(extra)
    return payload


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=_safe_payload(request, exc.status_code, str(exc.detail)),
        headers=getattr(exc, "headers", None),
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError,
) -> JSONResponse:
    """Ne renvoie que les erreurs sanitisÃ©es (loc/msg/type), pas le `input` (mots de passe)."""
    sanitized = [
        {"loc": list(e.get("loc", [])), "msg": e.get("msg"), "type": e.get("type")}
        for e in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=_safe_payload(
            request, 422, "DonnÃ©es de requÃªte invalides", {"errors": sanitized},
        ),
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """500 : log serveur complet, message client gÃ©nÃ©rique."""
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


async def rate_limit_exceeded_handler(
    request: Request, exc: RateLimitExceeded,
) -> JSONResponse:
    """Handler dÃ©diÃ© au 429 (slowapi)."""
    logger.warning(
        "Rate limit exceeded on %s %s (request_id=%s, client=%s)",
        request.method, request.url.path,
        getattr(request.state, "request_id", None),
        request.client.host if request.client else "?",
    )
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content=_safe_payload(request, 429, "Trop de requÃªtes, veuillez rÃ©essayer plus tard"),
        headers={"Retry-After": "60"},
    )
