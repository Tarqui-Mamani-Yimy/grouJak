from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app.config import get_settings
from backend.app.main import create_app
from backend.app.schemas import iso_z, utcnow
from backend.app.store import get_db

HEADERS = {"X-API-Key": "test-key"}
HOST = "app-login-demo"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("API_KEY", "test-key")
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "")
    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
        time.sleep(0.15)
    get_settings.cache_clear()


def login_event(
    event_type: str = "login_failed",
    *,
    ip: str = "203.0.113.7",
    user: str = "ana",
) -> dict:
    return {
        "timestamp": iso_z(utcnow()),
        "source_ip": ip,
        "event_type": event_type,
        "user": user,
        "host": HOST,
    }


def post_events(client: TestClient, events: list[dict], key: str = "test-key"):
    return client.post(
        "/api/v1/events",
        headers={"X-API-Key": key},
        json={"events": events},
    )


def create_alert(client: TestClient) -> dict:
    response = post_events(
        client, [login_event() for _ in range(5)]
    )
    assert response.status_code == 200
    alerts = response.json()["alerts_created"]
    assert len(alerts) == 1
    return alerts[0]


def wait_for_analysis(client: TestClient, alert_id: int) -> dict:
    for _ in range(80):
        alerts = client.get("/api/v1/alerts").json()
        alert = next((item for item in alerts if item["id"] == alert_id), None)
        if alert and alert["ai_result"] is not None:
            return alert
        time.sleep(0.05)
    raise AssertionError("La alerta no recibió ai_result")


def test_events_require_api_key(client: TestClient) -> None:
    response = client.post("/api/v1/events", json={"events": [login_event()]})
    assert response.status_code == 401


def test_company_in_body_is_rejected(client: TestClient) -> None:
    payload = {"company": "otra", "events": [login_event()]}
    response = client.post("/api/v1/events", headers=HEADERS, json=payload)
    assert response.status_code == 422


def test_password_field_is_rejected(client: TestClient) -> None:
    event = login_event()
    event["password"] = "no-debe-viajar"
    response = post_events(client, [event])
    assert response.status_code == 422


def test_brute_force_alert_and_dedup(client: TestClient) -> None:
    alert = create_alert(client)
    assert alert["rule"] == "brute_force"
    assert alert["count"] == 5
    assert alert["source_ip"] == "203.0.113.7"
    assert alert["created_at"].endswith("Z")

    response = post_events(client, [login_event() for _ in range(2)])
    assert response.status_code == 200
    updated = response.json()["alerts_created"]
    assert len(updated) == 1
    assert updated[0]["id"] == alert["id"]
    assert updated[0]["count"] == 7

    alerts = client.get("/api/v1/alerts").json()
    assert len(alerts) == 1


def test_ai_fallback_is_saved_without_telegram(client: TestClient) -> None:
    alert = create_alert(client)
    analyzed = wait_for_analysis(client, alert["id"])
    assert analyzed["ai_result"]["confidence"] == 0.0
    assert analyzed["ai_result"]["severity"] == "medium"
    assert analyzed["notified"] is False


def test_success_after_failures_escalates_same_alert(client: TestClient) -> None:
    alert = create_alert(client)
    response = post_events(client, [login_event("login_success")])
    assert response.status_code == 200
    updated = response.json()["alerts_created"]
    assert len(updated) == 1
    assert updated[0]["id"] == alert["id"]
    assert updated[0]["rule"] == "success_after_failures"
    assert updated[0]["user"] == "ana"

    alerts = client.get("/api/v1/alerts").json()
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "success_after_failures"


def test_block_ip_mitigates_correlated_findings(client: TestClient) -> None:
    db = get_db()
    finding = db.upsert_finding(
        host=HOST,
        check="no_rate_limit",
        severity="high",
        detail="Login sin límite de intentos.",
        detected_at=datetime.now(timezone.utc),
    )
    alert = create_alert(client)
    assert alert["correlated_finding_ids"] == [finding.id]

    mismatch = client.post(
        "/api/v1/block-ip",
        json={"ip": "198.51.100.9", "alert_id": alert["id"]},
    )
    assert mismatch.status_code == 400

    response = client.post(
        "/api/v1/block-ip",
        json={"ip": alert["source_ip"], "alert_id": alert["id"]},
    )
    assert response.status_code == 200
    assert response.json() == {"blocked": True}
    assert db.is_blocked("203.0.113.7")

    mitigated = client.get("/api/v1/findings").json()
    assert mitigated[0]["status"] == "mitigated"
    assert client.get("/api/v1/alerts").json()[0]["blocked"] is True


def test_attacker_target_cannot_be_supplied(client: TestClient) -> None:
    response = client.post(
        "/api/v1/attacker/run",
        json={"mode": "scripted", "target": "http://example.com"},
    )
    assert response.status_code == 422


def test_demo_alert_endpoint(client: TestClient) -> None:
    response = client.post("/api/v1/demo/alert")
    assert response.status_code == 200
    alert = response.json()
    assert alert["rule"] == "success_after_failures"
    assert alert["host"] == HOST
    assert len(client.get("/api/v1/alerts").json()) == 1
