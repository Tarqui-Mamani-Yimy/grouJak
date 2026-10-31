from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator, Sequence

from .schemas import AIResult, Alert, Event, Finding, iso_z, parse_utc, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user_name TEXT NOT NULL,
    host TEXT NOT NULL,
    company TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_window
    ON events (host, source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_time
    ON events (timestamp);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    check_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    detected_at TEXT NOT NULL,
    UNIQUE (host, check_name)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL,
    host TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    user_name TEXT NOT NULL,
    failure_count INTEGER NOT NULL,
    window_seconds INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    correlated_finding_ids TEXT NOT NULL DEFAULT '[]',
    ai_result TEXT,
    notified INTEGER NOT NULL DEFAULT 0,
    notified_rule TEXT,
    telegram_message_id INTEGER,
    blocked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup
    ON alerts (source_ip, host, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_created
    ON alerts (created_at);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    alert_id INTEGER,
    created_at TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout=10000")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init(self) -> None:
        with self._lock, self.connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)

    def insert_events(self, events: Sequence[Event], company: str) -> None:
        received_at = iso_z(utcnow())
        rows = [
            (
                iso_z(event.timestamp),
                event.source_ip,
                event.event_type,
                event.user,
                event.host,
                company,
                received_at,
            )
            for event in events
        ]
        with self._lock, self.connection() as conn:
            conn.executemany(
                """
                INSERT INTO events
                    (timestamp, source_ip, event_type, user_name, host, company, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def events_since(self, since: datetime) -> list[Event]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT timestamp, source_ip, event_type, user_name, host
                FROM events
                WHERE timestamp >= ?
                ORDER BY timestamp ASC, id ASC
                LIMIT 10000
                """,
                (iso_z(since),),
            ).fetchall()
        return [
            Event(
                timestamp=parse_utc(row["timestamp"]),
                source_ip=row["source_ip"],
                event_type=row["event_type"],
                user=row["user_name"],
                host=row["host"],
            )
            for row in rows
        ]

    def upsert_finding(
        self,
        *,
        host: str,
        check: str,
        severity: str,
        detail: str,
        detected_at: datetime,
    ) -> Finding:
        with self._lock, self.connection() as conn:
            conn.execute(
                """
                INSERT INTO findings (host, check_name, severity, detail, status, detected_at)
                VALUES (?, ?, ?, ?, 'open', ?)
                ON CONFLICT(host, check_name) DO UPDATE SET
                    severity = excluded.severity,
                    detail = excluded.detail,
                    status = 'open',
                    detected_at = excluded.detected_at
                """,
                (host, check, severity, detail, iso_z(detected_at)),
            )
            row = conn.execute(
                "SELECT * FROM findings WHERE host = ? AND check_name = ?",
                (host, check),
            ).fetchone()
        return self._finding(row)

    def list_findings(self) -> list[Finding]:
        with self.connection() as conn:
            rows = conn.execute("SELECT * FROM findings ORDER BY id ASC").fetchall()
        return [self._finding(row) for row in rows]

    def findings_by_ids(self, ids: Sequence[int]) -> list[Finding]:
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        with self.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM findings WHERE id IN ({placeholders}) ORDER BY id ASC",
                tuple(ids),
            ).fetchall()
        return [self._finding(row) for row in rows]

    def correlated_finding_ids(self, host: str) -> list[int]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT id FROM findings WHERE host = ? AND status = 'open' ORDER BY id ASC",
                (host,),
            ).fetchall()
        return [int(row["id"]) for row in rows]

    def create_alert(
        self,
        *,
        rule: str,
        host: str,
        source_ip: str,
        user: str,
        count: int,
        window_seconds: int,
        correlated_finding_ids: Sequence[int],
    ) -> Alert:
        now = iso_z(utcnow())
        with self._lock, self.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO alerts
                    (rule, host, source_ip, user_name, failure_count, window_seconds,
                     created_at, updated_at, correlated_finding_ids, notified, blocked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
                """,
                (
                    rule,
                    host,
                    source_ip,
                    user,
                    count,
                    window_seconds,
                    now,
                    now,
                    json.dumps(list(correlated_finding_ids)),
                ),
            )
            alert_id = int(cursor.lastrowid)
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return self._alert(row)

    def get_alert(self, alert_id: int) -> Alert | None:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return self._alert(row) if row else None

    def find_open_alert(self, source_ip: str, host: str, since: datetime) -> Alert | None:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM alerts
                WHERE source_ip = ? AND host = ? AND blocked = 0 AND created_at >= ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (source_ip, host, iso_z(since)),
            ).fetchone()
        return self._alert(row) if row else None

    def alerts_for_success(
        self, host: str, source_ip: str, user: str, since: datetime
    ) -> list[Alert]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM alerts
                WHERE host = ? AND blocked = 0 AND created_at >= ?
                  AND (source_ip = ? OR user_name = ?)
                ORDER BY id ASC
                """,
                (host, iso_z(since), source_ip, user),
            ).fetchall()
        return [self._alert(row) for row in rows]

    def bump_alert(
        self,
        alert_id: int,
        *,
        count: int,
        user: str | None = None,
        correlated_finding_ids: Sequence[int] | None = None,
    ) -> Alert | None:
        with self._lock, self.connection() as conn:
            conn.execute(
                """
                UPDATE alerts
                SET failure_count = ?,
                    user_name = COALESCE(?, user_name),
                    correlated_finding_ids = COALESCE(?, correlated_finding_ids),
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    count,
                    user,
                    json.dumps(list(correlated_finding_ids))
                    if correlated_finding_ids is not None
                    else None,
                    iso_z(utcnow()),
                    alert_id,
                ),
            )
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return self._alert(row) if row else None

    def escalate_alert(
        self,
        alert_id: int,
        *,
        rule: str,
        user: str,
        count: int,
        window_seconds: int,
        correlated_finding_ids: Sequence[int],
    ) -> Alert | None:
        with self._lock, self.connection() as conn:
            conn.execute(
                """
                UPDATE alerts
                SET rule = ?,
                    user_name = ?,
                    failure_count = ?,
                    window_seconds = ?,
                    correlated_finding_ids = ?,
                    ai_result = NULL,
                    notified = 0,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    rule,
                    user,
                    count,
                    window_seconds,
                    json.dumps(list(correlated_finding_ids)),
                    iso_z(utcnow()),
                    alert_id,
                ),
            )
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return self._alert(row) if row else None

    def set_alert_analysis(
        self,
        alert_id: int,
        result: AIResult,
        correlated_finding_ids: Sequence[int],
    ) -> Alert | None:
        with self._lock, self.connection() as conn:
            conn.execute(
                """
                UPDATE alerts
                SET ai_result = ?,
                    correlated_finding_ids = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    json.dumps(result.model_dump(mode="json"), ensure_ascii=False),
                    json.dumps(list(correlated_finding_ids)),
                    iso_z(utcnow()),
                    alert_id,
                ),
            )
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return self._alert(row) if row else None

    def mark_alert_notified(
        self, alert_id: int, rule: str, telegram_message_id: int | None
    ) -> None:
        with self._lock, self.connection() as conn:
            conn.execute(
                """
                UPDATE alerts
                SET notified = ?,
                    notified_rule = ?,
                    telegram_message_id = COALESCE(?, telegram_message_id)
                WHERE id = ?
                """,
                (1 if telegram_message_id is not None else 0, rule, telegram_message_id, alert_id),
            )

    def get_notified_rule(self, alert_id: int) -> str | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT notified_rule FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
        return row["notified_rule"] if row else None

    def get_telegram_message_id(self, alert_id: int) -> int | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT telegram_message_id FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
        return int(row["telegram_message_id"]) if row and row["telegram_message_id"] else None

    def list_alerts(self, since_id: int | None = None) -> list[Alert]:
        query = "SELECT * FROM alerts"
        params: tuple = ()
        if since_id is not None:
            query += " WHERE id > ?"
            params = (since_id,)
        query += " ORDER BY id ASC LIMIT 500"
        with self.connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._alert(row) for row in rows]

    def is_blocked(self, ip: str) -> bool:
        with self.connection() as conn:
            row = conn.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
        return row is not None

    def apply_block(self, ip: str, alert_id: int) -> list[int]:
        now = iso_z(utcnow())
        with self._lock, self.connection() as conn:
            conn.execute(
                """
                INSERT INTO blocked_ips (ip, alert_id, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    alert_id = excluded.alert_id,
                    created_at = excluded.created_at
                """,
                (ip, alert_id, now),
            )
            row = conn.execute(
                "SELECT correlated_finding_ids FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            finding_ids = json.loads(row["correlated_finding_ids"]) if row else []
            conn.execute(
                "UPDATE alerts SET blocked = 1, updated_at = ? WHERE id = ?",
                (now, alert_id),
            )
            for finding_id in finding_ids:
                conn.execute(
                    "UPDATE findings SET status = 'mitigated' WHERE id = ?",
                    (int(finding_id),),
                )
        return [int(item) for item in finding_ids]

    @staticmethod
    def _finding(row: sqlite3.Row) -> Finding:
        return Finding(
            id=int(row["id"]),
            host=row["host"],
            check=row["check_name"],
            severity=row["severity"],
            detail=row["detail"],
            status=row["status"],
            detected_at=parse_utc(row["detected_at"]),
        )

    @staticmethod
    def _alert(row: sqlite3.Row) -> Alert:
        ai_raw = row["ai_result"]
        ai_result = AIResult.model_validate_json(ai_raw) if ai_raw else None
        return Alert(
            id=int(row["id"]),
            rule=row["rule"],
            host=row["host"],
            source_ip=row["source_ip"],
            user=row["user_name"],
            count=int(row["failure_count"]),
            window_seconds=int(row["window_seconds"]),
            created_at=parse_utc(row["created_at"]),
            correlated_finding_ids=[int(item) for item in json.loads(row["correlated_finding_ids"])],
            ai_result=ai_result,
            notified=bool(row["notified"]),
            blocked=bool(row["blocked"]),
        )


_db: Database | None = None


def init_db(path: Path) -> Database:
    global _db
    _db = Database(path)
    _db.init()
    return _db


def get_db() -> Database:
    if _db is None:
        raise RuntimeError("La base de datos no está inicializada")
    return _db
