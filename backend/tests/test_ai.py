from datetime import datetime, timezone

from backend.app.ai import enforce_rule_floor, fallback_result, parse_ai_result
from backend.app.schemas import AIResult, Alert, Finding

ALERT = Alert(
    id=1,
    rule="success_after_failures",
    host="app-login-demo",
    source_ip="203.0.113.7",
    user="ana",
    count=24,
    window_seconds=60,
    created_at=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
)

FINDING = Finding(
    id=7,
    host="app-login-demo",
    check="no_rate_limit",
    severity="high",
    detail="El login no bloquea tras fallos repetidos",
    status="open",
    detected_at=datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc),
)


def test_parse_ai_result_accepts_fenced_json() -> None:
    text = """```json
{"severity": "critical", "explanation": "Hubo 24 intentos desde 203.0.113.7.",
 "probable_cause": "Login sin límite.", "recommended_actions": ["Bloquear IP"],
 "confidence": 0.92}
```"""
    result = parse_ai_result(text)
    assert result is not None
    assert result.severity == "critical"
    assert result.confidence == 0.92


def test_parse_ai_result_rejects_invalid_confidence() -> None:
    text = '{"severity": "high", "explanation": "x", "probable_cause": "y", "recommended_actions": ["z"], "confidence": 7}'
    assert parse_ai_result(text) is None


def test_fallback_uses_rules_not_ai_and_mentions_finding() -> None:
    result = fallback_result(ALERT, [FINDING])
    assert result.severity == "high"
    assert "203.0.113.7" in result.explanation
    assert "limita" in result.probable_cause
    assert result.confidence == 0.0


def test_rule_floor_raises_ai_severity() -> None:
    result = AIResult(
        severity="low",
        explanation="x",
        probable_cause="y",
        recommended_actions=["z"],
        confidence=0.5,
    )
    assert enforce_rule_floor(result, "success_after_failures").severity == "high"
    assert enforce_rule_floor(result, "brute_force").severity == "medium"


def test_rule_floor_keeps_critical() -> None:
    result = AIResult(
        severity="critical",
        explanation="x",
        probable_cause="y",
        recommended_actions=["z"],
        confidence=0.9,
    )
    assert enforce_rule_floor(result, "success_after_failures").severity == "critical"
