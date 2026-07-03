from __future__ import annotations

import logging

from elasticsearch import AsyncElasticsearch

from app.config import settings

logger = logging.getLogger("elasticsearch")
_es_client: AsyncElasticsearch | None = None


def get_es_client() -> AsyncElasticsearch:
    """Retourne le client ES singleton (créé au premier appel)."""
    global _es_client
    if _es_client is None:
        _es_client = _create_client()
    return _es_client


def _create_client() -> AsyncElasticsearch:
    kwargs: dict = {
        "hosts": [settings.ELASTICSEARCH_HOST],
        "basic_auth": (settings.ELASTICSEARCH_USERNAME, settings.ELASTICSEARCH_PASSWORD),
        "verify_certs": settings.ELASTICSEARCH_TLS_VERIFY,
        "request_timeout": settings.ELASTICSEARCH_REQUEST_TIMEOUT,
        "max_retries": settings.ELASTICSEARCH_MAX_RETRIES,
        "retry_on_timeout": False,
        "http_compress": True,
        "connections_per_node": 10,
        "sniff_on_start": False,
    }
    if settings.ELASTICSEARCH_CA_CERTS:
        kwargs["ca_certs"] = settings.ELASTICSEARCH_CA_CERTS
    return AsyncElasticsearch(**kwargs)


async def es_ping() -> bool:
    """Ping l'endpoint ES. Utilisé par /health."""
    try:
        es = get_es_client()
        return bool(await es.ping())
    except Exception as exc:
        logger.warning("ES ping failed: %s", exc)
        return False


async def close_es_client() -> None:
    """Ferme proprement la connexion ES (au shutdown)."""
    global _es_client
    if _es_client:
        await _es_client.close()
        _es_client = None
