from __future__ import annotations

import logging
from time import perf_counter
from urllib.parse import urlparse

import httpx

from .config import SCAN_PROBE_HEADER, SCAN_PROBE_VALUE, get_settings
from .schemas import Finding, utcnow
from .store import get_db

logger = logging.getLogger(__name__)

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "X-Frame-Options",
    "Content-Security-Policy",
)
EXPOSED_PATHS = ("/.env", "/.git/config", "/admin")
RATE_LIMIT_ATTEMPTS = 8


class ScannerError(RuntimeError):
    pass


async def run_scan() -> list[Finding]:
    settings = get_settings()
    target = settings.demo_app_url
    checks: list[tuple[str, str, str]] = []
    probe_headers = {SCAN_PROBE_HEADER: SCAN_PROBE_VALUE}

    async with httpx.AsyncClient(
        timeout=10.0,
        follow_redirects=False,
        headers=probe_headers,
    ) as client:
        try:
            root = await client.get(f"{target}/")
        except httpx.HTTPError as exc:
            raise ScannerError("No se pudo alcanzar la app de demo") from exc

        missing = [name for name in SECURITY_HEADERS if name not in root.headers]
        if missing:
            checks.append(
                (
                    "missing_headers",
                    "medium",
                    "Faltan cabeceras de seguridad: " + ", ".join(missing) + ".",
                )
            )

        exposed: list[str] = []
        for path in EXPOSED_PATHS:
            try:
                response = await client.get(f"{target}{path}")
            except httpx.HTTPError:
                continue
            if response.status_code == 200:
                exposed.append(path)
        if exposed:
            checks.append(
                (
                    "exposed_path",
                    "high",
                    "Rutas accesibles sin autenticación: " + ", ".join(exposed) + ".",
                )
            )

        if urlparse(target).scheme.lower() != "https":
            checks.append(
                (
                    "no_https",
                    "medium",
                    "La aplicación responde solo por HTTP; no se detecta redirección forzada a HTTPS.",
                )
            )

        statuses: list[int] = []
        durations: list[float] = []
        for _ in range(RATE_LIMIT_ATTEMPTS):
            started = perf_counter()
            try:
                response = await client.post(
                    f"{target}/login",
                    data={
                        "username": "scan_probe",
                        "password": "invalid-scan-probe-only",
                    },
                )
            except httpx.HTTPError as exc:
                raise ScannerError("No se pudo completar la prueba de login") from exc
            statuses.append(response.status_code)
            durations.append(perf_counter() - started)

        protected = any(status in {403, 423, 429} for status in statuses)
        delayed = max(durations) > 1.5 or (sum(durations) / len(durations)) > 0.8
        if not protected and not delayed:
            checks.append(
                (
                    "no_rate_limit",
                    "high",
                    f"{RATE_LIMIT_ATTEMPTS} intentos de login fallidos consecutivos "
                    "sin bloqueo, retraso progresivo ni código 429.",
                )
            )

    db = get_db()
    detected_at = utcnow()
    findings: list[Finding] = []
    for check, severity, detail in checks:
        findings.append(
            db.upsert_finding(
                host=settings.demo_host,
                check=check,
                severity=severity,
                detail=detail,
                detected_at=detected_at,
            )
        )
    logger.info("Escaneo completado con %s hallazgos", len(findings))
    return findings
