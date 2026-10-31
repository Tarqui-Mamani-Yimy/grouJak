from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

SCAN_PROBE_HEADER = "X-Scan-Probe"
SCAN_PROBE_VALUE = "sentinel-local-scan"
DEMO_CLIENT_IP_HEADER = "X-Demo-Client-IP"
DEMO_HOST_FALLBACK = "app-login-demo"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    api_key: str = "dev-api-key-change-me"
    company_name: str = "Demo Pyme"
    database_path: str = "./data/sentinel.db"

    demo_app_url: str = "http://127.0.0.1:8080"
    demo_host: str = DEMO_HOST_FALLBACK
    backend_url: str = "http://127.0.0.1:8000"
    demo_user: str = "ana"
    demo_password: str = "demo1234"
    demo_attacker_source_ip: str = "203.0.113.7"

    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 60
    alert_dedup_seconds: int = 300

    anthropic_api_key: str = ""
    claude_model: str = "claude-sonnet-5-5"

    max_attack_steps: int = 15
    attacker_timeout_seconds: int = 120

    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    @model_validator(mode="after")
    def _validate(self) -> "Settings":
        for name in ("brute_force_threshold", "brute_force_window_seconds", "alert_dedup_seconds"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} debe ser mayor que cero")
        if self.max_attack_steps < 1:
            raise ValueError("max_attack_steps debe ser mayor que cero")
        self.demo_app_url = self._loopback_url(self.demo_app_url, "demo_app_url")
        self.backend_url = self._loopback_url(self.backend_url, "backend_url")
        if not self.demo_host.strip():
            raise ValueError("demo_host no puede estar vacío")
        if not self.demo_user.strip() or not self.demo_password:
            raise ValueError("Las credenciales de demo no pueden estar vacías")
        self.demo_attacker_source_ip = str(
            ipaddress.ip_address(self.demo_attacker_source_ip)
        )
        return self

    @staticmethod
    def _loopback_url(value: str, name: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in LOOPBACK_HOSTS:
            raise ValueError(f"{name} debe apuntar a la app de demo en loopback")
        return value.rstrip("/")

    @property
    def database_file(self) -> Path:
        path = Path(self.database_path)
        return path if path.is_absolute() else PROJECT_ROOT / path

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)

    @property
    def ai_enabled(self) -> bool:
        return bool(self.anthropic_api_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()
