"""
exceptions.py — Gestionnaires d'erreurs HTTP personnalisés
Responsable : Chef de Projet & Sécurité
"""

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError


async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "status_code": exc.status_code,
            "detail": exc.detail,
            "path": str(request.url),
        },
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "error": True,
            "status_code": 422,
            "detail": "Données de requête invalides",
            "errors": exc.errors(),
            "path": str(request.url),
        },
    )


async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "status_code": 500,
            "detail": "Erreur interne du serveur",
            "path": str(request.url),
        },
    )
