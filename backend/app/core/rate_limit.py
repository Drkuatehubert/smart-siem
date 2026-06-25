"""
rate_limit.py â€” Limiter slowapi (brute-force, scraping, etc.)

Responsable : Chef de Projet & SÃ©curitÃ©
Exigences : NFR-SEC-04 (anti brute-force login, anti scraping)

Le limiter est instanciÃ© ici pour Ãªtre rÃ©utilisÃ© comme dÃ©corateur
sur les endpoints sensibles (`@limiter.limit("5/minute")`).

Stockage : Redis (database 1, sÃ©parÃ©e du stream principal de logs).
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings


def _key_func(request) -> str:
    """
    Key function : IP cliente rÃ©elle (en tenant compte de X-Forwarded-For
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
