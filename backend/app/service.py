from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Sequence

from .config import get_settings
from .processor import process_alert
from .rules import evaluate_events
from .schemas import Alert, Event, utcnow
from .store import get_db
from .ws import manager

logger = logging.getLogger(__name__)

_ingest_lock = asyncio.Lock()
_tasks: set[asyncio.Task] = set()


def schedule_processing(alert_id: int) -> None:
    task = asyncio.create_task(process_alert(alert_id))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


async def _publish(alert: Alert) -> None:
    await manager.broadcast(
        {"type": "alert_new", "alert": alert.model_dump(mode="json")}
    )


async def ingest_events(events: Sequence[Event], company: str) -> list[Alert]:
    settings = get_settings()
    now = utcnow()

    async with _ingest_lock:
        db = get_db()
        db.insert_events(events, company)

        recent = db.events_since(
            now - timedelta(seconds=settings.brute_force_window_seconds)
        )
        candidates = evaluate_events(
            recent,
            now=now,
            threshold=settings.brute_force_threshold,
            window_seconds=settings.brute_force_window_seconds,
        )

        dedup_since = now - timedelta(seconds=settings.alert_dedup_seconds)
        affected: dict[int, Alert] = {}
        to_process: set[int] = set()

        for candidate in candidates:
            existing = db.find_open_alert(
                candidate.source_ip, candidate.host, dedup_since
            )
            finding_ids = db.correlated_finding_ids(candidate.host)

            if existing is None:
                alert = db.create_alert(
                    rule=candidate.rule,
                    host=candidate.host,
                    source_ip=candidate.source_ip,
                    user=candidate.user,
                    count=candidate.count,
                    window_seconds=candidate.window_seconds,
                    correlated_finding_ids=finding_ids,
                )
                to_process.add(alert.id)
            else:
                escalated = (
                    existing.rule == "brute_force"
                    and candidate.rule == "success_after_failures"
                )
                if escalated:
                    alert = db.escalate_alert(
                        existing.id,
                        rule=candidate.rule,
                        user=candidate.user,
                        count=max(existing.count, candidate.count),
                        window_seconds=candidate.window_seconds,
                        correlated_finding_ids=finding_ids,
                    )
                    to_process.add(existing.id)
                else:
                    alert = db.bump_alert(
                        existing.id,
                        count=max(existing.count, candidate.count),
                        user=candidate.user,
                        correlated_finding_ids=finding_ids,
                    )

            if alert is not None:
                affected[alert.id] = alert
                await _publish(alert)

        for success in (event for event in events if event.event_type == "login_success"):
            for alert in db.alerts_for_success(
                success.host, success.source_ip, success.user, dedup_since
            ):
                if alert.rule != "brute_force":
                    continue
                finding_ids = db.correlated_finding_ids(alert.host)
                updated = db.escalate_alert(
                    alert.id,
                    rule="success_after_failures",
                    user=success.user,
                    count=alert.count,
                    window_seconds=settings.brute_force_window_seconds,
                    correlated_finding_ids=finding_ids,
                )
                if updated is not None:
                    affected[updated.id] = updated
                    to_process.add(updated.id)
                    await _publish(updated)

        for alert_id in to_process:
            schedule_processing(alert_id)

        return sorted(affected.values(), key=lambda alert: alert.id)


async def create_demo_alert() -> Alert:
    settings = get_settings()
    db = get_db()
    finding_ids = db.correlated_finding_ids(settings.demo_host)
    alert = db.create_alert(
        rule="success_after_failures",
        host=settings.demo_host,
        source_ip="198.51.100.23",
        user="demo_pyme",
        count=12,
        window_seconds=settings.brute_force_window_seconds,
        correlated_finding_ids=finding_ids,
    )
    await _publish(alert)
    schedule_processing(alert.id)
    return alert


async def block_alert_ip(alert_id: int, ip: str) -> tuple[Alert, list[int]]:
    db = get_db()
    alert = db.get_alert(alert_id)
    if alert is None:
        raise LookupError("Alerta no encontrada")
    if alert.source_ip != ip:
        raise ValueError("La IP no coincide con la alerta")

    finding_ids = db.apply_block(ip, alert_id)
    updated = db.get_alert(alert_id)
    if updated is None:
        raise LookupError("Alerta no encontrada")
    await manager.broadcast(
        {
            "type": "blocked",
            "ip": ip,
            "alert_id": alert_id,
            "blocked": True,
            "finding_ids": finding_ids,
        }
    )
    return updated, finding_ids
