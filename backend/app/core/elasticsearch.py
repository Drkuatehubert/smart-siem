from __future__ import annotations

import logging

from elasticsearch import AsyncElasticsearch

from app.config import settings

logger = logging.getLogger("elasticsearch")
# Singleton du client ES, partagé par toute l'application pour réutiliser le pool de connexions.
_es_client: AsyncElasticsearch | None = None


def get_es_client() -> AsyncElasticsearch:
    """Retourne le client ES singleton (créé au premier appel)."""
    global _es_client
    if _es_client is None:
        _es_client = _create_client()
    return _es_client


def _create_client() -> AsyncElasticsearch:
    # Rassemble tous les paramètres de connexion dans un dict pour pouvoir en ajouter
    # certains conditionnellement (ca_certs) avant l'appel final.
    kwargs: dict = {
        "hosts": [settings.ELASTICSEARCH_HOST],
        "basic_auth": (settings.ELASTICSEARCH_USERNAME, settings.ELASTICSEARCH_PASSWORD),
        "verify_certs": settings.ELASTICSEARCH_TLS_VERIFY,   # vérifie le certificat TLS du serveur ES
        "request_timeout": settings.ELASTICSEARCH_REQUEST_TIMEOUT,
        "max_retries": settings.ELASTICSEARCH_MAX_RETRIES,
        "retry_on_timeout": False,
        "http_compress": True,
        "connections_per_node": 10,
        "sniff_on_start": False,
    }
    if settings.ELASTICSEARCH_CA_CERTS:
        # Si un certificat d'autorité de certification (CA) personnalisé est fourni,
        # on l'utilise pour valider le certificat du serveur (cas d'un ES auto-signé).
        kwargs["ca_certs"] = settings.ELASTICSEARCH_CA_CERTS
    return AsyncElasticsearch(**kwargs)


async def es_ping() -> bool:
    """Ping l'endpoint ES. Utilisé par /health."""
    try:
        es = get_es_client()
        return bool(await es.ping())
    except Exception as exc:
        # On ne propage pas l'exception : le endpoint /health doit répondre même
        # si Elasticsearch est injoignable, en signalant simplement "dependencies.elasticsearch: false".
        logger.warning("ES ping failed: %s", exc)
        return False


async def close_es_client() -> None:
    """Ferme proprement la connexion ES (au shutdown)."""
    global _es_client
    if _es_client:
        await _es_client.close()
        _es_client = None

    # Ferme proprement le verrou de synchronisation.
    await _es_lock.acquire()
    await _es_lock.release()