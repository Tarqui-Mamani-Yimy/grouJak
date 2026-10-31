from __future__ import annotations

import ipaddress
import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from backend.app.config import (
    DEMO_CLIENT_IP_HEADER,
    LOOPBACK_HOSTS,
    SCAN_PROBE_HEADER,
    SCAN_PROBE_VALUE,
    get_settings,
)
from backend.app.schemas import iso_z, utcnow
from backend.app.store import get_db, init_db

logger = logging.getLogger(__name__)

LOGIN_PAGE = """<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Portal de clientes · Demo</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; display: grid; place-items: center;
      font-family: system-ui, -apple-system, Segoe UI, sans-serif;
      background: radial-gradient(circle at 20% 20%, #1b2a3a, #070b10 65%);
      color: #e7edf3;
    }
    .card {
      width: min(420px, 92vw); padding: 36px; border-radius: 18px;
      background: rgba(15, 23, 32, .92); border: 1px solid #26394d;
      box-shadow: 0 20px 60px rgba(0,0,0,.45);
    }
    .badge {
      display: inline-block; font-size: 11px; letter-spacing: .14em;
      text-transform: uppercase; color: #79d4ff; border: 1px solid #24516b;
      padding: 4px 8px; border-radius: 999px; margin-bottom: 20px;
    }
    h1 { margin: 0 0 6px; font-size: 24px; }
    p { margin: 0 0 24px; color: #8fa3b7; font-size: 14px; line-height: 1.5; }
    label { display: block; font-size: 12px; color: #9fb2c4; margin: 14px 0 6px; }
    input {
      width: 100%; padding: 11px 12px; border-radius: 9px; border: 1px solid #2c4055;
      background: #0a1118; color: #eaf2fa; font-size: 15px; outline: none;
    }
    input:focus { border-color: #3b8bb8; }
    button {
      width: 100%; margin-top: 22px; padding: 12px; border: 0; border-radius: 9px;
      background: linear-gradient(135deg, #1f8fce, #1564a3); color: white;
      font-size: 15px; font-weight: 650; cursor: pointer;
    }
    .hint { margin-top: 22px; font-size: 11px; color: #6c7f91; }
  </style>
</head>
<body>
  <main class="card">
    <span class="badge">Entorno de demostración</span>
    <h1>Portal de clientes</h1>
    <p>Aplicación de login usada únicamente para la demostración de seguridad local.</p>
    <form method="post" action="/login" autocomplete="off">
      <label for="username">Usuario</label>
      <input id="username" name="username" required maxlength="64">
      <label for="password">Contraseña</label>
      <input id="password" name="password" type="password" required maxlength="128">
      <button type="submit">Ingresar</button>
    </form>
    <div class="hint">Demo local · app-login-demo</div>
  </main>
</body>
</html>"""

ADMIN_PAGE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>Admin</title></head>
<body style="font-family:system-ui;background:#101820;color:#e8eef5;padding:40px">
<h1>Panel de administración</h1>
<p>Ruta de demostración expuesta sin autenticación.</p>
<ul><li>Usuarios: 128</li><li>Pedidos pendientes: 14</li><li>Último acceso: hace 2 h</li></ul>
</body></html>"""

FAKE_ENV = """APP_ENV=demo
DEMO_ONLY=true
DATABASE_URL=sqlite:///demo.db
SECRET_KEY=not-a-real-secret-demo-only
"""

FAKE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
[remote "origin"]
\turl = https://example.invalid/demo/app-login.git
"""

ROBOTS_TXT = """User-agent: *
Disallow: /admin
Disallow: /backup.sql
Disallow: /.env
"""

SERVER_STATUS = """server: uvicorn/demo
status: ok
uptime: 42m
requests: 1337
"""

FAKE_BACKUP = """-- Synthetic demo backup. No real credentials or data.
CREATE TABLE users (id INTEGER, username TEXT, password_hash TEXT);
-- demo rows intentionally omitted
"""

FAKE_DEBUG = """Traceback (most recent call last):
  File "demo_app/main.py", line 42, in login
    validate_credentials(user)
RuntimeError: synthetic demo trace, no real data
"""

FAKE_METRICS = """# HELP demo_requests_total Synthetic demo metric
# TYPE demo_requests_total counter
demo_requests_total{path="/login"} 42
demo_requests_total{path="/admin"} 7
"""


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db(get_settings().database_file)
    yield


app = FastAPI(title="App de login demo", lifespan=lifespan)


def _client_ip(request: Request) -> str:
    real_ip = request.client.host if request.client else "127.0.0.1"
    if real_ip in LOOPBACK_HOSTS:
        candidate = request.headers.get(DEMO_CLIENT_IP_HEADER)
        if candidate:
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                pass
    return real_ip


def _is_scan(request: Request) -> bool:
    real_ip = request.client.host if request.client else "127.0.0.1"
    return (
        real_ip in LOOPBACK_HOSTS
        and request.headers.get(SCAN_PROBE_HEADER, "") == SCAN_PROBE_VALUE
    )


def _clean_user(value: str) -> str:
    cleaned = "".join(ch for ch in value if ch.isprintable()).strip()
    return (cleaned or "desconocido")[:128]


async def _send_login_event(event_type: str, user: str, source_ip: str) -> None:
    settings = get_settings()
    payload = {
        "events": [
            {
                "timestamp": iso_z(utcnow()),
                "source_ip": source_ip,
                "event_type": event_type,
                "user": user,
                "host": settings.demo_host,
            }
        ]
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{settings.backend_url}/api/v1/events",
                json=payload,
                headers={"X-API-Key": settings.api_key},
            )
            if response.status_code >= 400:
                logger.warning(
                    "El backend rechazó un evento de login (%s)", response.status_code
                )
    except Exception as exc:
        logger.warning("No se pudo enviar el evento al backend (%s)", type(exc).__name__)


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return LOGIN_PAGE


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(default=""),
    password: str = Form(default=""),
) -> PlainTextResponse:
    settings = get_settings()
    source_ip = _client_ip(request)
    scan_request = _is_scan(request)

    if not scan_request and get_db().is_blocked(source_ip):
        return PlainTextResponse(
            "Acceso bloqueado por política de seguridad.", status_code=403
        )

    user = _clean_user(username)
    success = user == settings.demo_user and password == settings.demo_password

    if not scan_request:
        await _send_login_event(
            "login_success" if success else "login_failed",
            settings.demo_user if success else user,
            source_ip,
        )

    if success:
        response = PlainTextResponse(
            f"Acceso concedido. Bienvenida, {settings.demo_user}."
        )
        response.set_cookie(
            "demo_session",
            "demo-session-token",
            httponly=True,
            samesite="lax",
        )
        return response
    return PlainTextResponse("Credenciales inválidas.", status_code=401)


# Vulnerabilidades intencionales de la demo: rutas expuestas, sin cabeceras de seguridad,
# HTTP sin TLS y login sin límite de intentos.
@app.get("/admin", response_class=HTMLResponse)
async def admin() -> str:
    return ADMIN_PAGE


@app.get("/.env", response_class=PlainTextResponse)
async def fake_env() -> str:
    return FAKE_ENV


@app.get("/.git/config", response_class=PlainTextResponse)
async def fake_git_config() -> str:
    return FAKE_GIT_CONFIG


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots() -> str:
    return ROBOTS_TXT


@app.get("/server-status", response_class=PlainTextResponse)
async def server_status() -> str:
    return SERVER_STATUS


@app.get("/api/users")
async def fake_users() -> dict:
    return {
        "source": "synthetic-demo",
        "users": [get_settings().demo_user, "admin", "soporte"],
    }


@app.get("/backup.sql", response_class=PlainTextResponse)
async def fake_backup() -> str:
    return FAKE_BACKUP


@app.get("/debug", response_class=PlainTextResponse)
async def fake_debug() -> str:
    return FAKE_DEBUG


@app.get("/metrics", response_class=PlainTextResponse)
async def fake_metrics() -> str:
    return FAKE_METRICS


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
