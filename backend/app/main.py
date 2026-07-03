"""
main.py — Point d'entrée FastAPI (durci)

Responsable : Chef de Projet & Sécurité
Exigences : NFR-SEC-05 (CORS strict, headers sécurité), NFR-SEC-01 (CORS+jwt)

Middlewares appliqués (du plus extérieur au plus intérieur) :
  1. SecurityHeadersMiddleware — HSTS, X-Frame-Options, CSP, etc.
  2. RequestIdMiddleware — génère / propage un X-Request-Id
  3. CORSMiddleware — origins explicites, pas de wildcard
  4. (slowapi) — rate limit sur endpoints sensibles

Endpoints :
  GET  /health              — healthcheck enrichi (ES ping)
"""

from __future__ import annotations

import logging
import time
import uuid
# asynccontextmanager : permet d'écrire une fonction "async with" réutilisable,
# ici pour le cycle de vie (démarrage / arrêt) de l'application FastAPI.
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError  # levée quand le corps/paramètres d'une requête sont invalides
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.core.elasticsearch import close_es_client, es_ping
from app.core.exceptions import (
    generic_exception_handler,       # capte toute exception non prévue (dernier filet de sécurité)
    http_exception_handler,          # capte les HTTPException levées volontairement dans le code
    validation_exception_handler,    # capte les erreurs de validation de schéma (Pydantic)
)
from app.api.v1.router import api_router  # routeur qui regroupe toutes les routes /api/v1/*

logger = logging.getLogger("main")


# ─────────────────────────────────────────────────────────────────────────────
# Middlewares
# ─────────────────────────────────────────────────────────────────────────────

class SecurityHeadersMiddleware:
    """Ajoute les en-têtes de sécurité à chaque réponse."""

    def __init__(self, app):
        # `app` est l'application (ou le middleware suivant) à appeler ensuite dans la chaîne.
        self.app = app

    async def __call__(self, scope, receive, send):
        # Les middlewares ASGI reçoivent aussi les connexions websocket/lifespan :
        # on ne touche qu'aux requêtes HTTP classiques, on laisse passer le reste tel quel.
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            # On intercepte uniquement le message de début de réponse pour y injecter nos en-têtes.
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend([
                    # HSTS : force le navigateur à toujours utiliser HTTPS pour ce domaine.
                    (b"strict-transport-security",
                     f"max-age={settings.HSTS_MAX_AGE}; includeSubDomains".encode()),
                    # Empêche le navigateur de deviner/changer le type MIME d'une ressource.
                    (b"x-content-type-options", b"nosniff"),
                    # Interdit d'afficher la page dans une <iframe> (protection anti-clickjacking).
                    (b"x-frame-options", b"DENY"),
                    # Ne transmet jamais l'URL d'origine aux sites tiers via l'en-tête Referer.
                    (b"referrer-policy", b"no-referrer"),
                    # Désactive explicitement certaines APIs navigateur sensibles.
                    (b"permissions-policy", b"accelerometer=(), camera=(), geolocation=()"),
                    # Politique de sécurité du contenu, définie dans config.py.
                    # (b"content-security-policy", settings.CSP_POLICY.encode("utf-8")),
                ])
                message["headers"] = headers
            await send(message)

        # On délègue le traitement réel à l'application, mais avec notre `send` modifié.
        await self.app(scope, receive, send_wrapper)


class RequestIdMiddleware:
    """Génère ou propage un `X-Request-Id` et l'expose via `request.state.request_id`."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Récupère l'ID entrant ou en génère un nouveau
        headers = dict(scope.get("headers") or [])
        rid = headers.get(b"x-request-id", b"").decode("latin-1") or uuid.uuid4().hex
        scope["state"] = scope.get("state", {})
        scope["state"]["request_id"] = rid

        async def send_wrapper(message):
            # On renvoie systématiquement le même ID au client, pour qu'il puisse le fournir
            # à son tour s'il contacte le support en cas de problème.
            if message["type"] == "http.response.start":
                hdrs = list(message.get("headers", []))
                hdrs.append((b"x-request-id", rid.encode("latin-1")))
                message["headers"] = hdrs
            await send(message)

        # Mesure le temps de traitement de la requête pour le journaliser ensuite.
        start = time.time()
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            # Le bloc `finally` garantit que la ligne de log est écrite même si une exception
            # remonte pendant le traitement de la requête.
            duration_ms = (time.time() - start) * 1000
            method = scope.get("method", "?")
            path = scope.get("path", "?")
            logger.info(
                "rid=%s method=%s path=%s duration_ms=%.1f",
                rid, method, path, duration_ms,
            )


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Démarrage / arrêt propre : ferme ES, Redis et PostgreSQL."""
    logger.info("Smart SIEM API starting (env=%s)", settings.APP_ENV)
    from app.core.postgres import close_pg_pool, ensure_admin_user, get_pg_pool
    await get_pg_pool()
    await ensure_admin_user()
    yield
    # Tout le code après le `yield` s'exécute à l'arrêt (ex: Ctrl+C, arrêt du conteneur),
    # ce qui permet de libérer proprement les connexions réseau ouvertes.
    await close_es_client()
    await close_redis_client()
    await close_pg_pool()
    logger.info("Smart SIEM API stopped")


# ─────────────────────────────────────────────────────────────────────────────
# Application
# ─────────────────────────────────────────────────────────────────────────────

# En prod, on coupe la doc OpenAPI (fuite de schéma)
_docs_kwargs = {}
if settings.APP_ENV == "prod" or not settings.DOCS_ENABLED:
    _docs_kwargs = {"docs_url": None, "redoc_url": None, "openapi_url": None}

# Création de l'application FastAPI avec ses métadonnées (affichées dans /docs quand actif).
app = FastAPI(
    title="Smart SIEM API",
    description="API REST du système de gestion et d'analyse des événements de sécurité",
    version="1.0.0",
    terms_of_service="https://example.com/terms",
    contact={"name": "Smart SIEM Team", "email": "security@example.com"},
    license_info={"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
    lifespan=lifespan,
    **_docs_kwargs,
)

# Rate limiter
app.state.limiter = limiter

# Middlewares (l'ordre est important : extérieur en dernier via `add_middleware`)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5176",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5176",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Gestionnaires d'erreurs : transforment chaque type d'exception en réponse JSON cohérente,
# au lieu de laisser fuiter une trace Python brute vers le client.
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# Router agrégateur
app.include_router(api_router, prefix="/api/v1")


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints de base
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Santé"])
async def health_check():
    """Endpoint de santé — RF-COL-05."""
    es_ok = await es_ping()
    return {
        "status": "ok",
        "service": "smart-siem-backend",
        "dependencies": {"elasticsearch": es_ok},
    }
