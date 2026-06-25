"""conftest.py — Fixtures pytest globales"""
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture
def client():
    return TestClient(app)
