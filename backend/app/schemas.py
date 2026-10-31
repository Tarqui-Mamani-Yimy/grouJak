from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    field_validator,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def iso_z(value: datetime) -> str:
    return _ensure_utc(value).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    return _ensure_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


UtcDateTime = Annotated[
    datetime,
    AfterValidator(_ensure_utc),
    PlainSerializer(iso_z, return_type=str, when_used="json"),
]

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def clean_text(value: str) -> str:
    return _CONTROL_CHARS.sub(" ", value).strip()


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: UtcDateTime
    source_ip: str
    event_type: Literal["login_failed", "login_success"]
    user: str = Field(max_length=128)
    host: str = Field(max_length=128)

    @field_validator("source_ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value.strip()))

    @field_validator("user", "host")
    @classmethod
    def _clean(cls, value: str) -> str:
        cleaned = clean_text(value)
        if not cleaned:
            raise ValueError("no puede estar vacío")
        return cleaned


class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[Event] = Field(min_length=1, max_length=500)


class Finding(BaseModel):
    id: int
    host: str
    check: Literal["missing_headers", "exposed_path", "no_https", "no_rate_limit"]
    severity: Literal["low", "medium", "high"]
    detail: str
    status: Literal["open", "mitigated"] = "open"
    detected_at: UtcDateTime


class AIResult(BaseModel):
    severity: Literal["low", "medium", "high", "critical"]
    explanation: str = Field(min_length=1, max_length=700)
    probable_cause: str = Field(min_length=1, max_length=500)
    recommended_actions: list[str] = Field(min_length=1, max_length=6)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("explanation", "probable_cause")
    @classmethod
    def _clean(cls, value: str) -> str:
        cleaned = clean_text(value)
        if not cleaned:
            raise ValueError("no puede estar vacío")
        return cleaned

    @field_validator("recommended_actions")
    @classmethod
    def _clean_actions(cls, value: list[str]) -> list[str]:
        actions = [clean_text(item)[:300] for item in value]
        actions = [item for item in actions if item]
        if not actions:
            raise ValueError("se requiere al menos una acción")
        return actions[:6]


class Alert(BaseModel):
    id: int
    rule: Literal["brute_force", "success_after_failures"]
    host: str
    source_ip: str
    user: str
    count: int
    window_seconds: int
    created_at: UtcDateTime
    correlated_finding_ids: list[int] = Field(default_factory=list)
    ai_result: AIResult | None = None
    notified: bool = False
    blocked: bool = False


class AttackerLogLine(BaseModel):
    timestamp: UtcDateTime = Field(default_factory=utcnow)
    action: Literal[
        "recon",
        "probe_path",
        "brute_force_attempt",
        "brute_force_success",
        "blocked",
    ]
    detail: str = Field(min_length=1, max_length=800)

    @field_validator("detail")
    @classmethod
    def _clean(cls, value: str) -> str:
        cleaned = clean_text(value)
        if not cleaned:
            raise ValueError("no puede estar vacío")
        return cleaned[:800]


class BlockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str
    alert_id: int = Field(ge=1)

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value.strip()))


class AttackerRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["scripted", "agentic"]
