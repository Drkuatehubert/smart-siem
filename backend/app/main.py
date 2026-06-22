"""
main.py — Point d'entrée FastAPI
Responsable : Chef de Projet & Sécurité (structure et sécurité globale)
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

from app.config import settings
from app.core.elasticsearch import close_es_client
from app.core.exceptions import (
    http_exception_handler,
    validation_exception_handler,
    generic_exception_handler,
)
from app.api.v1.auth.router import router as auth_router
from app.api.v1.audit.router import router as audit_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    yield
    # Shutdown
    await close_es_client()


app = FastAPI(
    title="Smart SIEM API",
    description="API REST du système de gestion et d'analyse des événements de sécurité",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Gestionnaires d'erreurs ────────────────────
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# ── Routers ───────────────────────────────────
app.include_router(auth_router,  prefix="/api/v1")
app.include_router(audit_router, prefix="/api/v1")


@app.get("/health", tags=["Santé"])
async def health_check():
    """Endpoint de santé — RF-COL-05."""
    return {"status": "ok", "service": "smart-siem-backend"}
