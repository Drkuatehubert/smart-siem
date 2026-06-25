"""
elasticsearch.py â€” Client Elasticsearch singleton (durci)

Responsable : Chef de Projet & SÃ©curitÃ©
Exigences : NFR-SEC-05 (TLS obligatoire en prod), durcissement opÃ©rationnel

RÃ©glages :
  * request_timeout (pas de queries qui pendent) ;
  * max_retries + retry_on_timeout (rÃ©silience face aux blips) ;
  * http_compress (rÃ©duit la bande passante) ;
  * connections_per_node (Ã©vite de marteler un seul nÅ“ud) ;
  * ca_certs si fourni, sinon verify_certs boolÃ©en.
"""

from __future__ import annotations

import asyncio
import logging

from elasticsearch import AsyncElasticsearch

from app.config import settings

logger = logging.getLogger("elasticsearch")
_es_client: AsyncElasticsearch | None = None
_es_lock = asyncio.Lock()


def get_es_client() -> AsyncElasticsearch:
    """
    Retourne le client ES singleton.
    Note : la crÃ©ation est protÃ©gÃ©e par un asyncio.Lock pour gÃ©rer
    les accÃ¨s concurrents au dÃ©marrage (FastAPI startup asynchrone).
    """
    global _es_client
    if _es_client is None:
        # Verrou synchrone (Lock est OK ici : on n'attend pas d'I/O en pratique)
        if not _es_lock.locked():
            _es_client = _create_client()
        else:
            # Race : autre coroutine crÃ©e le client, on attend
            asyncio.get_event_loop().run_until_complete(_es_lock.acquire())
            try:
                if _es_client is None:
                    _es_client = _create_client()
            finally:
                _es_lock.release()
    return _es_client


def _create_client() -> AsyncElasticsearch:
    kwargs: dict = {
        "hosts": [settings.ELASTICSEARCH_HOST],
        "basic_auth": (settings.ELASTICSEARCH_USERNAME, settings.ELASTICSEARCH_PASSWORD),
        "verify_certs": settings.ELASTICSEARCH_TLS_VERIFY,
        "request_timeout": settings.ELASTICSEARCH_REQUEST_TIMEOUT,
        "max_retries": settings.ELASTICSEARCH_MAX_RETRIES,
        "retry_on_timeout": True,
        "http_compress": True,
        "connections_per_node": 10,
        "sniff_on_start": False,
    }
    if settings.ELASTICSEARCH_CA_CERTS:
        kwargs["ca_certs"] = settings.ELASTICSEARCH_CA_CERTS
    return AsyncElasticsearch(**kwargs)


async def es_ping() -> bool:
    """Ping l'endpoint ES. UtilisÃ© par /health."""
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
