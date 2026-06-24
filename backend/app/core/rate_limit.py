"""
rate_limit.py — Limiter slowapi (brute-force, scraping, etc.)

Responsable : Chef de Projet & Sécurité
Exigences : NFR-SEC-04 (anti brute-force login, anti scraping)

Le limiter est instancié ici pour être réutilisé comme décorateur
sur les endpoints sensibles (`@limiter.limit("5/minute")`).

Stockage : Redis (database 1, séparée du stream principal de logs).
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings


def _key_func(request) -> str:
    """
    Key function : IP cliente réelle (en tenant compte de X-Forwarded-For
    si un proxy est devant l'API). En production, s'assurer que l'IP source
    est de confiance via Nginx.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return get_remote_address(request)


limiter = Limiter(
    key_func=_key_func,
    storage_uri=settings.RATE_LIMIT_STORAGE_URI,
    default_limits=[settings.RATE_LIMIT_DEFAULT],
    headers_enabled=True,
    strategy="fixed-window",
)
