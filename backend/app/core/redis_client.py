"""
redis_client.py — Client Redis (Streams + cache + révocation JWT)

Responsable : Chef de Projet & Sécurité
Exigences : NFR-SEC-05 (AUTH + TLS en prod), NFR-SEC-01 (révocation JTI)

Réglages :
  * AUTH via REDIS_PASSWORD ;
  * TLS optionnel (REDIS_TLS) ;
  * sockets bornés (timeouts) ;
  * publish_log : XADD avec MAXLEN, et taille message bornée ;
  * health-check périodique.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

import redis.asyncio as aioredis  # client Redis asynchrone (compatible async/await de FastAPI)

from app.config import settings

logger = logging.getLogger("redis")
# Variable de module qui garde l'unique instance du client Redis (pattern singleton) :
# on évite ainsi d'ouvrir une nouvelle connexion à chaque appel.
_redis_client: Optional[aioredis.Redis] = None


def get_redis_client() -> aioredis.Redis:
    """Singleton du client Redis (async)."""
    global _redis_client
    if _redis_client is None:
        # "rediss://" (avec un s) indique au client d'utiliser une connexion chiffrée TLS.
        scheme = "rediss" if settings.REDIS_TLS else "redis"
        auth = f":{settings.REDIS_PASSWORD}@" if settings.REDIS_PASSWORD else ""
        url = f"{scheme}://{auth}{settings.REDIS_HOST}:{settings.REDIS_PORT}/0"
        _redis_client = aioredis.from_url(
            url,
            decode_responses=True,          # renvoie des str Python plutôt que des bytes bruts
            socket_timeout=5,                # délai max d'attente d'une réponse Redis
            socket_connect_timeout=5,        # délai max pour établir la connexion initiale
            health_check_interval=30,        # vérifie périodiquement que la connexion est toujours valide
            ssl_cert_reqs="required" if settings.REDIS_TLS else None,
            ssl_ca_certs=settings.REDIS_CA_CERTS if settings.REDIS_TLS else None,
        )
    return _redis_client


async def close_redis_client() -> None:
    # Appelé au shutdown de l'application (voir lifespan dans main.py) pour libérer
    # proprement la connexion réseau plutôt que de la laisser ouverte jusqu'au kill du process.
    global _redis_client
    if _redis_client is not None:
        try:
            await _redis_client.aclose()
        except Exception:
            # On ignore les erreurs de fermeture : l'application est de toute façon en train de s'arrêter.
            pass
        _redis_client = None


async def publish_log(log: dict) -> None:
    """
    Publie un log brut dans le stream Redis (XADD avec MAXLEN).
    Lève si le message dépasse REDIS_MESSAGE_MAX_BYTES (anti-DoS).
    """
    # On sérialise le log en JSON avant de l'envoyer, car Redis Streams stocke des
    # champs texte/binaires, pas des objets Python.
    payload = json.dumps(log, ensure_ascii=False)
    if len(payload.encode("utf-8")) > settings.REDIS_MESSAGE_MAX_BYTES:
        # Empêche un agent de collecte compromis ou buggé d'envoyer un message géant
        # qui saturerait la mémoire du stream Redis.
        raise ValueError(
            f"Log trop volumineux (>{settings.REDIS_MESSAGE_MAX_BYTES} octets)"
        )
    r = get_redis_client()
    await r.xadd(
        settings.REDIS_STREAM_KEY,
        {"data": payload},
        maxlen=settings.REDIS_STREAM_MAXLEN,  # taille max du flux : les plus anciens messages sont purgés au-delà
        approximate=True,                      # purge approximative (moins coûteuse en performance que le mode exact)
    )
