from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

import app.core.elasticsearch as elasticsearch_module
from app.api.v1.auth import service as auth_service
from app.core.security import hash_password
from app.main import app


def test_login_and_logs_search_flow(monkeypatch):
    # Ce test est unitaire : il ne doit pas dépendre d'un vrai cluster Elasticsearch.
    # On simule donc le client ES avec un utilisateur "admin" déjà connu (hash bcrypt
    # valide pour le mot de passe "admin"). Deux points d'entrée à mocker :
    #  - app.api.v1.auth.service.get_es_client (authenticate_user, write_audit_log) ;
    #  - app.core.elasticsearch.get_es_client (require_validated_user, import local).
    mock_es = AsyncMock()
    mock_es.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_id": "user-1",
                    "_source": {
                        "username": "admin",
                        "password_hash": hash_password("admin"),
                        "role_id": "administrateur",
                        "org_scope": None,
                        "is_active": True,
                    },
                }
            ]
        }
    }
    mock_es.get.return_value = {
        "_source": {
            "username": "admin",
            "role_id": "administrateur",
            "org_scope": None,
            "is_active": True,
        }
    }
    monkeypatch.setattr(auth_service, "get_es_client", lambda: mock_es)
    monkeypatch.setattr(elasticsearch_module, "get_es_client", lambda: mock_es)

    client = TestClient(app)

    login_response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert login_response.status_code == 200
    payload = login_response.json()
    assert payload["access_token"]

    # require_permission("logs:read") exige un token Bearer valide : on réutilise
    # celui obtenu au login (le rôle "administrateur" a la permission logs:read).
    search_response = client.post(
        "/api/v1/logs/search",
        json={"query": "Authentication", "source": "normalizer-api"},
        headers={"Authorization": f"Bearer {payload['access_token']}"},
    )
    assert search_response.status_code == 200
    body = search_response.json()
    assert body["total"] >= 1
    assert body["results"][0]["source"] == "normalizer-api"
