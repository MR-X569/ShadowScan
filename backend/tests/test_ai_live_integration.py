"""
tests/test_ai_live_integration.py
---------------------------------
Live integration tests for ShadowScan AI Security Analyst with running Ollama instance.
Automatically skipped if Ollama is not running or model is not pulled.
"""

import pytest
import httpx
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.core.enums import ScanStatus, Severity, UserRole
from app.core.security import hash_password, create_access_token
from app.main import app
from app.core.config import settings
from app.ai.ollama import OllamaClient


def is_ollama_live() -> bool:
    """Check if local Ollama server is running and configured model is available."""
    try:
        resp = httpx.get(f"{settings.ollama_base_url}/api/tags", timeout=2.0)
        if resp.status_code != 200:
            return False
        models = [m.get("name", "") for m in resp.json().get("models", [])]
        # Check if configured model name is in models list
        return any(settings.ollama_model in m for m in models)
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not is_ollama_live(),
    reason="Local Ollama server is not running or model is not downloaded.",
)


@pytest.fixture
def live_db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSession()

    user = User(
        username="live_ai_tester",
        email="live_ai@example.com",
        hashed_password=hash_password("Password123!"),
        role=UserRole.USER,
        is_verified=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    scan = Scan(
        user_id=user.id,
        target_url="https://test-target.example.com",
        status=ScanStatus.COMPLETED,
        risk_score=6.5,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    f1 = Finding(
        scan_id=scan.id,
        vulnerability_name="Missing Content-Security-Policy Header",
        plugin="security_headers",
        severity=Severity.HIGH,
        description="No CSP header was returned by the web server.",
        recommendation="Configure a restrictive Content-Security-Policy header.",
    )
    db.add(f1)
    db.commit()

    yield db, user, scan, f1

    db.close()
    Base.metadata.drop_all(bind=engine)


def test_live_ai_chat_remediation_query(live_db_session):
    db, user, scan, f1 = live_db_session

    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    token = create_access_token({"sub": user.username})
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.post(
        f"/scans/{scan.id}/ai/chat",
        headers=headers,
        json={"message": "How do I remediate finding #1?", "history": []},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["ai_status"] == "ready"
    assert data["model_used"] == settings.ollama_model
    assert data["is_refusal"] is False
    assert len(data["response"]) > 20
    assert "CSP" in data["response"] or "Content-Security-Policy" in data["response"] or "header" in data["response"]

    app.dependency_overrides.clear()


def test_live_ai_chat_multi_turn(live_db_session):
    db, user, scan, f1 = live_db_session

    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    token = create_access_token({"sub": user.username})
    headers = {"Authorization": f"Bearer {token}"}

    history = [
        {"role": "user", "content": "How do I fix missing CSP?"},
        {"role": "assistant", "content": "You can add Content-Security-Policy: default-src 'self' to your server headers."},
    ]

    resp = client.post(
        f"/scans/{scan.id}/ai/chat",
        headers=headers,
        json={"message": "Can you show me an example for Nginx?", "history": history},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["ai_status"] == "ready"
    assert "add_header" in data["response"] or "nginx" in data["response"].lower() or "server" in data["response"].lower()

    app.dependency_overrides.clear()
