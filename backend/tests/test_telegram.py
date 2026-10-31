from datetime import datetime, timezone

from backend.app.ai import fallback_result
from backend.app.attacker import _sanitize
from backend.app.config import get_settings
from backend.app.schemas import Alert, Finding
from backend.app.telegram import build_message


def test_telegram_message_has_context_and_no_password() -> None:
    finding = Finding(
        id=1,
        host="app-login-demo",
        check="no_rate_limit",
        severity="high",
        detail="Login sin límite de intentos.",
        status="open",
        detected_at=datetime.now(timezone.utc),
    )
    alert = Alert(
        id=3,
        rule="success_after_failures",
        host="app-login-demo",
        source_ip="203.0.113.7",
        user="ana",
        count=24,
        window_seconds=60,
        created_at=datetime.now(timezone.utc),
        correlated_finding_ids=[1],
    )
    alert = alert.model_copy(update={"ai_result": fallback_result(alert, [finding])})
    message = build_message(alert)

    assert "Éxito tras fallos" in message
    assert "203.0.113.7" in message
    assert "24" in message
    assert "ana" in message
    assert get_settings().demo_password not in message


def test_attacker_sanitizes_demo_password() -> None:
    password = get_settings().demo_password
    sanitized = _sanitize(f"Probando la clave {password} contra el login.")
    assert password not in sanitized
    assert "[credencial oculta]" in sanitized
