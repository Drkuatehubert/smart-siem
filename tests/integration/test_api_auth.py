"""test_api_auth.py — Tests intégration /auth"""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

def test_login_no_body():
    r = client.post("/api/v1/auth/login", json={})
    assert r.status_code == 422

def test_me_no_token():
    r = client.get("/api/v1/auth/me")
    assert r.status_code == 401

