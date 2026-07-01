from fastapi.testclient import TestClient

from app.main import app


def test_login_and_logs_search_flow():
    client = TestClient(app)

    login_response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert login_response.status_code == 200
    payload = login_response.json()
    assert payload["access_token"]

    search_response = client.post(
        "/api/v1/logs/search",
        json={"query": "Authentication", "source": "normalizer-api"},
    )
    assert search_response.status_code == 200
    body = search_response.json()
    assert body["total"] >= 1
    assert body["results"][0]["source"] == "normalizer-api"
