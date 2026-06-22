"""
elasticsearch.py — Client Elasticsearch singleton
Responsable : Chef de Projet & Sécurité
"""

from elasticsearch import AsyncElasticsearch
from app.config import settings

_es_client: AsyncElasticsearch | None = None


def get_es_client() -> AsyncElasticsearch:
    """Retourne le client ES singleton (thread-safe)."""
    global _es_client
    if _es_client is None:
        _es_client = AsyncElasticsearch(
            hosts=[settings.ELASTICSEARCH_HOST],
            basic_auth=(settings.ELASTICSEARCH_USERNAME, settings.ELASTICSEARCH_PASSWORD),
            verify_certs=settings.ELASTICSEARCH_TLS_VERIFY,
        )
    return _es_client


async def close_es_client():
    """Ferme proprement la connexion ES (appeler au shutdown)."""
    global _es_client
    if _es_client:
        await _es_client.close()
        _es_client = None
