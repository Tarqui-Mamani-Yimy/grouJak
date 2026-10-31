from datetime import datetime, timedelta, timezone

from backend.app.rules import evaluate_events
from backend.app.schemas import Event

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
HOST = "app-login-demo"


def event(
    *,
    offset: int,
    event_type: str,
    ip: str = "203.0.113.7",
    user: str = "ana",
) -> Event:
    return Event(
        timestamp=NOW - timedelta(seconds=offset),
        source_ip=ip,
        event_type=event_type,
        user=user,
        host=HOST,
    )


def evaluate(events: list[Event], threshold: int = 5, window: int = 60):
    return evaluate_events(events, now=NOW, threshold=threshold, window_seconds=window)


def test_below_threshold_creates_nothing() -> None:
    events = [event(offset=index, event_type="login_failed") for index in range(4)]
    assert evaluate(events) == []


def test_brute_force_creates_candidate() -> None:
    events = [event(offset=index, event_type="login_failed") for index in range(5)]
    candidates = evaluate(events)
    assert len(candidates) == 1
    assert candidates[0].rule == "brute_force"
    assert candidates[0].count == 5
    assert candidates[0].source_ip == "203.0.113.7"
    assert candidates[0].host == HOST


def test_success_after_failures_uses_success_user() -> None:
    events = [event(offset=10 + index, event_type="login_failed") for index in range(5)]
    events.append(event(offset=1, event_type="login_success", user="ana"))
    candidates = evaluate(events)
    assert len(candidates) == 1
    assert candidates[0].rule == "success_after_failures"
    assert candidates[0].user == "ana"


def test_old_failures_outside_window_are_ignored() -> None:
    events = [event(offset=120 + index, event_type="login_failed") for index in range(5)]
    assert evaluate(events) == []


def test_success_before_failures_does_not_escalate() -> None:
    events = [event(offset=20, event_type="login_success")]
    events.extend(event(offset=10 + index, event_type="login_failed") for index in range(5))
    candidates = evaluate(events)
    assert len(candidates) == 1
    assert candidates[0].rule == "brute_force"


def test_different_ips_are_separated() -> None:
    events = [
        event(offset=index, event_type="login_failed", ip="203.0.113.7")
        for index in range(5)
    ]
    events.extend(
        event(offset=index, event_type="login_failed", ip="198.51.100.9")
        for index in range(3)
    )
    candidates = evaluate(events)
    assert len(candidates) == 1
    assert candidates[0].source_ip == "203.0.113.7"


def test_success_from_same_user_other_ip_escalates() -> None:
    events = [event(offset=10 + index, event_type="login_failed") for index in range(5)]
    events.append(
        event(
            offset=1,
            event_type="login_success",
            ip="198.51.100.9",
            user="ana",
        )
    )
    candidates = evaluate(events)
    assert len(candidates) == 1
    assert candidates[0].rule == "success_after_failures"
