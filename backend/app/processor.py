from __future__ import annotations

import asyncio
import logging

from . import telegram
from .ai import analyze_alert
from .store import get_db
from .ws import manager

logger = logging.getLogger(__name__)

_locks: dict[int, asyncio.Lock] = {}


def _lock_for(alert_id: int) -> asyncio.Lock:
    lock = _locks.get(alert_id)
    if lock is None:
        lock = asyncio.Lock()
        _locks[alert_id] = lock
    return lock


async def process_alert(alert_id: int) -> None:
    try:
        async with _lock_for(alert_id):
            for _ in range(4):
                db = get_db()
                alert = db.get_alert(alert_id)
                if alert is None:
                    return
                if db.get_notified_rule(alert_id) == alert.rule:
                    return

                findings = db.findings_by_ids(alert.correlated_finding_ids)
                result = await analyze_alert(alert, findings)

                latest = db.get_alert(alert_id)
                if latest is None:
                    return
                if latest.rule != alert.rule:
                    continue

                updated = db.set_alert_analysis(
                    alert_id, result, latest.correlated_finding_ids
                )
                if updated is None:
                    return

                await manager.broadcast(
                    {"type": "alert_new", "alert": updated.model_dump(mode="json")}
                )
                message_id = await telegram.notify_alert(updated)
                db.mark_alert_notified(alert_id, updated.rule, message_id)
                return
    except Exception as exc:
        logger.warning(
            "No se pudo procesar la alerta %s (%s)", alert_id, type(exc).__name__
        )
