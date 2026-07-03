"""conftest.py — Fixtures pytest globales"""
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.main import app

@pytest.fixture
def client():
    return TestClient(app)
