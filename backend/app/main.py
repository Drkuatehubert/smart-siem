"""
main.py â€” Point d'entrÃ©e FastAPI (durci)

Responsable : Chef de Projet & SÃ©curitÃ©
Exigences : NFR-SEC-05 (CORS strict, headers sÃ©curitÃ©), NFR-SEC-01 (CORS+jwt)

Middlewares appliquÃ©s (du plus extÃ©rieur au plus intÃ©rieur) :
  1. SecurityHeadersMiddleware â€” HSTS, X-Frame-Options, CSP, etc.
  2. RequestIdMiddleware â€” gÃ©nÃ¨re / propage un X-Request-Id
  3. CORSMiddleware â€” origins explicites, pas de wildcard
  4. (slowapi) â€” rate limit sur endpoints sensibles

Endpoints :
  GET  /health              â€” healthcheck enrichi (ES ping)
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.core.elasticsearch import close_es_client, es_ping
from app.core.exceptions import (
    generic_exception_handler,
    http_exception_handler,
    rate_limit_exceeded_handler,
    validation_exception_handler,
)
from app.core.rate_limit import limiter
from app.core.redis_client import close_redis_client
from app.api.v1.router import api_router

logger = logging.getLogger("main")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Middlewares
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class SecurityHeadersMiddleware:
    """Ajoute les en-tÃªtes de sÃ©curitÃ© Ã  chaque rÃ©ponse."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend([
                    (b"strict-transport-security",
                     f"max-age={settings.HSTS_MAX_AGE}; includeSubDomains".encode()),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"accelerometer=(), camera=(), geolocation=()"),
                    (b"content-security-policy", settings.CSP_POLICY.encode("utf-8")),
                ])
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


class RequestIdMiddleware:
    """GÃ©nÃ¨re ou propage un `X-Request-Id` et l'expose via `request.state.request_id`."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # RÃ©cupÃ¨re l'ID entrant ou en gÃ©nÃ¨re un nouveau
        headers = dict(scope.get("headers") or [])
        rid = headers.get(b"x-request-id", b"").decode("latin-1") or uuid.uuid4().hex
        scope["state"] = scope.get("state", {})
        scope["state"]["request_id"] = rid

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                hdrs = list(message.get("headers", []))
                hdrs.append((b"x-request-id", rid.encode("latin-1")))
                message["headers"] = hdrs
            await send(message)

        start = time.time()
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = (time.time() - start) * 1000
            method = scope.get("method", "?")
            path = scope.get("path", "?")
            logger.info(
                "rid=%s method=%s path=%s duration_ms=%.1f",
                rid, method, path, duration_ms,
            )


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Lifespan
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@asynccontextmanager
async def lifespan(app: FastAPI):
    """DÃ©marrage / arrÃªt propre : ferme ES et Redis."""
    logger.info("Smart SIEM API starting (env=%s)", settings.APP_ENV)
    yield
    await close_es_client()
    await close_redis_client()
    logger.info("Smart SIEM API stopped")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Application
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

# En prod, on coupe la doc OpenAPI (fuite de schÃ©ma)
_docs_kwargs = {}
if settings.APP_ENV == "prod" or not settings.DOCS_ENABLED:
    _docs_kwargs = {"docs_url": None, "redoc_url": None, "openapi_url": None}

app = FastAPI(
    title="Smart SIEM API",
    description="API REST du systÃ¨me de gestion et d'analyse des Ã©vÃ©nements de sÃ©curitÃ©",
    version="1.0.0",
    lifespan=lifespan,
    **_docs_kwargs,
)

# Rate limiter
app.state.limiter = limiter

# Middlewares (l'ordre est important : extÃ©rieur en dernier via `add_middleware`)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=False,  # API sur Bearer, pas de cookies
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-Id"],
    max_age=600,
)

# Gestionnaires d'erreurs
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# Router agrÃ©gateur (corrige le code mort de la version prÃ©cÃ©dente)
app.include_router(api_router, prefix="/api/v1")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Endpoints de base
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.get("/health", tags=["SantÃ©"])
async def health_check():
    """Endpoint de santÃ© â€” RF-COL-05."""
    es_ok = await es_ping()
    return {
        "status": "ok",
        "service": "smart-siem-backend",
        "dependencies": {"elasticsearch": es_ok},
    }
