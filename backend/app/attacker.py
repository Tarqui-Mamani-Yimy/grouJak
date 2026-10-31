from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any, Literal

import httpx

from .config import DEMO_CLIENT_IP_HEADER, get_settings
from .schemas import AttackerLogLine, clean_text
from .ws import manager

logger = logging.getLogger(__name__)

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "X-Frame-Options",
    "Content-Security-Policy",
)
FIXED_PATHS = ("/admin", "/.env", "/.git/config")
BASE_PASSWORDS = (
    "123456",
    "password",
    "12345678",
    "qwerty",
    "abc123",
    "letmein",
    "monkey",
    "dragon",
    "111111",
    "baseball",
    "iloveyou",
    "trustno1",
    "1234567",
    "sunshine",
    "master",
    "welcome",
    "shadow",
    "ashley",
    "football",
    "jesus",
    "michael",
    "ninja",
    "mustang",
)
MAX_TOOL_ATTEMPTS = 30

SYSTEM_PROMPT = """Eres un pentester autorizado probando SOLO una app de demo local. El objetivo es fijo y no puedes cambiarlo. Solo puedes actuar mediante las herramientas disponibles; no escribes ni ejecutas código libre. Narra cada paso en español, una frase corta por acción. Tu objetivo es probar si el login resiste fuerza bruta con la lista fija de credenciales: llama a probar_login repetidamente hasta tener éxito o agotar los intentos. Nunca escribas contraseñas ni credenciales en el texto."""

TOOLS = [
    {
        "name": "revisar_rutas",
        "description": "Prueba una lista fija de rutas comunes (/admin, /.env, /.git/config) contra el objetivo fijo.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "revisar_headers",
        "description": "Pide la página principal y devuelve qué cabeceras de seguridad faltan.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "probar_login",
        "description": "Intenta un login usando la siguiente credencial de una lista fija de prueba. Los parámetros usuario/clave son ignorados; nunca se usan credenciales reales.",
        "input_schema": {
            "type": "object",
            "properties": {
                "usuario": {"type": "string"},
                "clave": {"type": "string"},
            },
            "required": ["usuario", "clave"],
        },
    },
    {
        "name": "reportar_hallazgo",
        "description": "Registra un resumen de lo encontrado y por qué lo probó.",
        "input_schema": {
            "type": "object",
            "properties": {"resumen": {"type": "string"}},
            "required": ["resumen"],
        },
    },
]


def _credentials() -> list[str]:
    settings = get_settings()
    prefix = [item for item in BASE_PASSWORDS if item != settings.demo_password][:6]
    rest = [
        item
        for item in BASE_PASSWORDS
        if item != settings.demo_password and item not in prefix
    ]
    return (prefix + [settings.demo_password] + rest)[:24]


def _sanitize(text: str, limit: int = 700) -> str:
    cleaned = clean_text(text)
    cleaned = re.sub(r"\s+", " ", cleaned)
    secrets = [get_settings().demo_password, *BASE_PASSWORDS]
    for secret in sorted(set(secrets), key=len, reverse=True):
        if secret:
            cleaned = cleaned.replace(secret, "[credencial oculta]")
    return cleaned[:limit]


async def broadcast_line(action: str, detail: str) -> None:
    line = AttackerLogLine(action=action, detail=_sanitize(detail))
    await manager.broadcast(
        {"type": "attacker_log", "line": line.model_dump(mode="json")}
    )


def _client() -> httpx.AsyncClient:
    settings = get_settings()
    return httpx.AsyncClient(
        base_url=settings.demo_app_url,
        timeout=httpx.Timeout(10.0, connect=5.0),
        headers={DEMO_CLIENT_IP_HEADER: settings.demo_attacker_source_ip},
    )


def _missing_headers(response: httpx.Response) -> list[str]:
    return [name for name in SECURITY_HEADERS if name not in response.headers]


def _is_blocked(response: httpx.Response) -> bool:
    return response.status_code in {403, 423, 429}


async def _run_scripted() -> None:
    settings = get_settings()
    credentials = _credentials()
    await broadcast_line(
        "recon", "Objetivo fijo: app-login-demo. Iniciando reconocimiento autorizado."
    )

    async with _client() as client:
        try:
            root = await client.get("/")
        except httpx.HTTPError:
            await broadcast_line("recon", "Atacante detenido: el objetivo no responde.")
            return

        missing = _missing_headers(root)
        if missing:
            await broadcast_line(
                "recon",
                "Cabeceras de seguridad ausentes: " + ", ".join(missing) + ".",
            )
        else:
            await broadcast_line("recon", "No faltan las cabeceras revisadas.")

        for path in FIXED_PATHS:
            try:
                response = await client.get(path)
            except httpx.HTTPError:
                await broadcast_line("probe_path", f"Ruta {path}: sin respuesta.")
                continue
            if response.status_code == 200:
                await broadcast_line(
                    "probe_path", f"Ruta {path} accesible sin autenticación (HTTP 200)."
                )
            else:
                await broadcast_line(
                    "probe_path", f"Ruta {path} responde HTTP {response.status_code}."
                )

        total = len(credentials)
        for index, password in enumerate(credentials, start=1):
            try:
                response = await client.post(
                    "/login",
                    data={"username": settings.demo_user, "password": password},
                )
            except httpx.HTTPError:
                await broadcast_line(
                    "recon", "Atacante detenido: error de conexión con el objetivo."
                )
                return

            if _is_blocked(response):
                await broadcast_line(
                    "blocked",
                    f"Atacante detenido: IP bloqueada por el defensor "
                    f"(intento {index}/{total}).",
                )
                return

            if response.status_code == 200:
                await broadcast_line(
                    "brute_force_success",
                    f"Intento {index}/{total}: acceso concedido como "
                    f"'{settings.demo_user}'.",
                )
                await broadcast_line("recon", "Atacante detenido: acceso obtenido.")
                return

            await broadcast_line(
                "brute_force_attempt",
                f"Intento {index}/{total} contra '{settings.demo_user}': "
                "credenciales rechazadas.",
            )
            await asyncio.sleep(0.18)

    await broadcast_line("recon", "Atacante detenido: secuencia completada sin acceso.")


@dataclass
class ToolResult:
    summary: str
    action: str = "recon"
    blocked: bool = False
    success: bool = False


class Toolbox:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self.credentials = _credentials()
        self.index = 0
        self.attempts = 0

    async def execute(self, name: str, payload: dict[str, Any]) -> ToolResult:
        if name == "revisar_rutas":
            return await self.revisar_rutas()
        if name == "revisar_headers":
            return await self.revisar_headers()
        if name == "probar_login":
            return await self.probar_login()
        if name == "reportar_hallazgo":
            return self.reportar_hallazgo(str(payload.get("resumen", "")))
        return ToolResult("Herramienta no permitida.", action="recon")

    async def revisar_rutas(self) -> ToolResult:
        exposed: list[str] = []
        statuses: list[str] = []
        for path in FIXED_PATHS:
            try:
                response = await self.client.get(path)
            except httpx.HTTPError:
                statuses.append(f"{path}=sin respuesta")
                continue
            statuses.append(f"{path}={response.status_code}")
            if response.status_code == 200:
                exposed.append(path)
        if exposed:
            return ToolResult(
                "Rutas accesibles sin autenticación: " + ", ".join(exposed) + ".",
                action="probe_path",
            )
        return ToolResult(
            "No se detectaron rutas expuestas. Resultados: " + ", ".join(statuses) + ".",
            action="probe_path",
        )

    async def revisar_headers(self) -> ToolResult:
        response = await self.client.get("/")
        missing = _missing_headers(response)
        if missing:
            return ToolResult(
                "Cabeceras de seguridad ausentes: " + ", ".join(missing) + ".",
                action="recon",
            )
        return ToolResult("No faltan las cabeceras revisadas.", action="recon")

    async def probar_login(self) -> ToolResult:
        settings = get_settings()
        if self.attempts >= MAX_TOOL_ATTEMPTS:
            return ToolResult("Límite de intentos de login alcanzado.", action="recon")
        if self.index >= len(self.credentials):
            return ToolResult(
                "Sin credenciales de prueba restantes.", action="brute_force_attempt"
            )

        password = self.credentials[self.index]
        self.index += 1
        self.attempts += 1
        total = len(self.credentials)
        try:
            response = await self.client.post(
                "/login",
                data={"username": settings.demo_user, "password": password},
            )
        except httpx.HTTPError:
            return ToolResult(
                "Error de conexión con el objetivo.", action="recon"
            )

        if _is_blocked(response):
            return ToolResult(
                f"Atacante detenido: la IP fue bloqueada por el defensor "
                f"(intento {self.index}/{total}).",
                action="blocked",
                blocked=True,
            )
        if response.status_code == 200:
            return ToolResult(
                f"Intento {self.index}/{total}: acceso concedido como "
                f"'{settings.demo_user}'.",
                action="brute_force_success",
                success=True,
            )
        return ToolResult(
            f"Intento {self.index}/{total} contra '{settings.demo_user}': "
            "credenciales rechazadas.",
            action="brute_force_attempt",
        )

    def reportar_hallazgo(self, summary: str) -> ToolResult:
        return ToolResult(
            "Hallazgo registrado: " + _sanitize(summary, 300), action="recon"
        )


async def _run_agentic() -> None:
    settings = get_settings()
    if not settings.ai_enabled:
        await broadcast_line(
            "recon", "IA no configurada; ejecutando secuencia scripted de respaldo."
        )
        await _run_scripted()
        return

    from anthropic import AsyncAnthropic

    await broadcast_line(
        "recon", "Modelo atacante iniciado. Objetivo fijo: app-login-demo."
    )
    client = AsyncAnthropic(api_key=settings.anthropic_api_key, timeout=25.0)
    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": (
                "Decide qué revisar primero. Usa las herramientas y narra cada paso. "
                "El objetivo es comprobar la resistencia del login a fuerza bruta con la "
                "lista fija; sigue intentando logins hasta tener éxito o agotar intentos."
            ),
        }
    ]

    async with _client() as http_client:
        toolbox = Toolbox(http_client)
        for _ in range(settings.max_attack_steps):
            response = await client.messages.create(
                model=settings.claude_model,
                max_tokens=350,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            )

            assistant_blocks: list[dict[str, Any]] = []
            tool_uses: list[Any] = []
            for block in response.content:
                if getattr(block, "type", "") == "text" and block.text.strip():
                    await broadcast_line("recon", block.text)
                    assistant_blocks.append({"type": "text", "text": block.text})
                elif getattr(block, "type", "") == "tool_use":
                    assistant_blocks.append(
                        {
                            "type": "tool_use",
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        }
                    )
                    tool_uses.append(block)

            if assistant_blocks:
                messages.append({"role": "assistant", "content": assistant_blocks})

            if not tool_uses:
                messages.append(
                    {
                        "role": "user",
                        "content": "Continúa usando una de las herramientas disponibles.",
                    }
                )
                continue

            tool_results: list[dict[str, Any]] = []
            finished = False
            blocked = False
            success = False
            for tool_use in tool_uses:
                result = await toolbox.execute(tool_use.name, tool_use.input or {})
                await broadcast_line(result.action, result.summary)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_use.id,
                        "content": result.summary,
                    }
                )
                if result.blocked:
                    blocked = True
                    finished = True
                if result.success:
                    success = True
                    finished = True

            messages.append({"role": "user", "content": tool_results})
            if blocked:
                return
            if success:
                await broadcast_line("recon", "Atacante detenido: acceso obtenido.")
                return
            if finished:
                return

    await broadcast_line("recon", "Atacante detenido: límite de pasos alcanzado.")


class AttackerRunner:
    def __init__(self) -> None:
        self._running = False
        self._task: asyncio.Task | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, mode: Literal["scripted", "agentic"]) -> bool:
        if self._running:
            return False
        self._running = True
        self._task = asyncio.create_task(self._run(mode))
        return True

    async def _run(self, mode: str) -> None:
        settings = get_settings()
        try:
            await asyncio.wait_for(
                self._execute(mode), timeout=settings.attacker_timeout_seconds
            )
        except TimeoutError:
            await broadcast_line(
                "recon", "Atacante detenido: tiempo máximo de ejecución excedido."
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("El agente atacante falló (%s)", type(exc).__name__)
            await broadcast_line(
                "recon",
                f"Atacante detenido: error inesperado ({type(exc).__name__}).",
            )
        finally:
            self._running = False

    async def _execute(self, mode: str) -> None:
        if mode == "agentic":
            await _run_agentic()
        else:
            await _run_scripted()
