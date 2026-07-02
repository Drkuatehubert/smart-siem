"""
main.py — Point d'entrée FastAPI (durci)

Responsable : Chef de Projet & Sécurité
Exigences : NFR-SEC-05 (CORS strict, headers sécurité), NFR-SEC-01 (CORS+jwt)

Middlewares appliqués (du plus extérieur au plus intérieur) :
  1. SecurityHeadersMiddleware — HSTS, X-Frame-Options, CSP, etc.
  2. RequestIdMiddleware — génère / propage un X-Request-Id
  3. CORSMiddleware — origins explicites, pas de wildcard

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
# Un middleware ASGI est un objet appelable qui reçoit (scope, receive, send) et peut
# inspecter/modifier la requête ou la réponse avant/après de passer la main à l'application.

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

        # Récupère l'ID entrant ou en génère un nouveau.
        # Cet identifiant permet de retrouver toutes les traces de logs liées à une même requête,
        # même si elle traverse plusieurs services.
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
    """Démarrage / arrêt propre : ferme la connexion ES."""
    # Tout le code avant le `yield` s'exécute au démarrage de l'application.
    logger.info("Smart SIEM API starting (env=%s)", settings.APP_ENV)
    yield
    # Tout le code après le `yield` s'exécute à l'arrêt (ex: Ctrl+C, arrêt du conteneur),
    # ce qui permet de libérer proprement les connexions réseau ouvertes.
    await close_es_client()
    logger.info("Smart SIEM API stopped")


# ─────────────────────────────────────────────────────────────────────────────
# Application
# ─────────────────────────────────────────────────────────────────────────────

# En prod, on coupe la doc OpenAPI (fuite de schéma) : sans ces routes, un attaquant
# ne peut pas lister automatiquement tous les endpoints et leurs paramètres.
_docs_kwargs = {}
if settings.APP_ENV == "prod" or not settings.DOCS_ENABLED:
    _docs_kwargs = {"docs_url": None, "redoc_url": None, "openapi_url": None}

# Création de l'application FastAPI avec ses métadonnées (affichées dans /docs quand actif).
app = FastAPI(
    title="Smart SIEM API",
    description=(
        "API REST du backend Smart SIEM pour l'authentification, la recherche de logs, "
        "la gestion des alertes, des incidents, des règles de corrélation, des rapports "
        "et l'audit sécurité."
    ),
    version="1.0.0",
    terms_of_service="https://example.com/terms",
    contact={"name": "Smart SIEM Team", "email": "security@example.com"},
    license_info={"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
    lifespan=lifespan,
    **_docs_kwargs,
)

# Middlewares (l'ordre est important : extérieur en dernier via `add_middleware`).
# FastAPI empile les middlewares dans l'ordre inverse d'ajout : le dernier ajouté
# est donc le plus "extérieur" (exécuté en premier sur la requête entrante).
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=False,  # API sur Bearer, pas de cookies (donc pas besoin d'autoriser les credentials CORS)
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-Id"],
    max_age=600,  # durée en secondes pendant laquelle le navigateur met en cache la réponse "preflight" CORS
)

# Gestionnaires d'erreurs : transforment chaque type d'exception en réponse JSON cohérente,
# au lieu de laisser fuiter une trace Python brute vers le client.
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# Router agrégateur (corrige le code mort de la version précédente) :
# toutes les routes définies dans app/api/v1/* sont montées ici sous le préfixe /api/v1.
app.include_router(api_router, prefix="/api/v1")


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints de base
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Santé"])
async def health_check():
    """Endpoint de santé — RF-COL-05."""
    # Vérifie qu'Elasticsearch répond, pour distinguer "l'API tourne" de
    # "l'API tourne mais ne peut plus rien lire/écrire".
    es_ok = await es_ping()
    return {
        "status": "ok",
        "service": "smart-siem-backend",
        "dependencies": {"elasticsearch": es_ok},
    }
