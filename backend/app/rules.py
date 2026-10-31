from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Sequence

from .schemas import Event


@dataclass(frozen=True)
class AlertCandidate:
    rule: Literal["brute_force", "success_after_failures"]
    host: str
    source_ip: str
    user: str
    count: int
    window_seconds: int


def evaluate_events(
    events: Sequence[Event],
    *,
    now: datetime,
    threshold: int,
    window_seconds: int,
) -> list[AlertCandidate]:
    window_start = now - timedelta(seconds=window_seconds)
    recent = [event for event in events if event.timestamp >= window_start]

    failures: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in recent:
        if event.event_type == "login_failed":
            failures[(event.host, event.source_ip)].append(event)

    successes = [event for event in recent if event.event_type == "login_success"]
    candidates: list[AlertCandidate] = []

    for (host, source_ip), failed_events in failures.items():
        if len(failed_events) < threshold:
            continue

        failed_users = {event.user for event in failed_events}
        first_failure = min(event.timestamp for event in failed_events)
        matching_successes = [
            event
            for event in successes
            if event.host == host
            and event.timestamp >= first_failure
            and (event.source_ip == source_ip or event.user in failed_users)
        ]
        success = max(matching_successes, key=lambda event: event.timestamp, default=None)

        if success is not None:
            user = success.user
            rule: Literal["brute_force", "success_after_failures"] = "success_after_failures"
        else:
            user = Counter(event.user for event in failed_events).most_common(1)[0][0]
            rule = "brute_force"

        candidates.append(
            AlertCandidate(
                rule=rule,
                host=host,
                source_ip=source_ip,
                user=user,
                count=len(failed_events),
                window_seconds=window_seconds,
            )
        )

    return candidates
