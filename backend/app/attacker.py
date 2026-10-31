from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Literal

import httpx

from .config import DEMO_CLIENT_IP_HEADER, get_settings
from .groq_client import extract_content, groq_chat_completion
from .schemas import AttackerLogLine, clean_text
from .ws import manager

logger = logging.getLogger(__name__)

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "X-Frame-Options",
    "Content-Security-Policy",
)
FIXED_PATHS = (
    "/robots.txt",
    "/admin",
    "/.env",
    "/.git/config",
    "/backup.sql",
    "/api/users",
    "/debug",
    "/server-status",
    "/metrics",
    "/openapi.json",
    "/docs",
)
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
SPRAY_USERS = ("admin", "soporte")
SPRAY_PASSWORDS = BASE_PASSWORDS[:3]
MAX_TOOL_ATTEMPTS = 30

SYSTEM_PROMPT = """Eres GROWJAk, el operador de una campaña de red team autorizada contra una app de demo local y aislada. El objetivo es fijo (app-login-demo) y no puedes cambiarlo. Solo actúas mediante las herramientas disponibles; no ejecutas código libre, no sales del sandbox y no exfiltres datos reales. Metodología: fingerprinting, enumeración de superficie y usuarios, credential access (password spraying y guessing con la lista fija), acceso inicial y post-explotación. Narra cada acción en español técnico en UNA sola frase de máximo 25 palabras; no uses Markdown, no repitas el informe y cita técnicas MITRE ATT&CK cuando aplique (T1595, T1083, T1087, T1110, T1078). No inventes objetivos y no menciones valores de credenciales, ni siquiera inventados."""

AGENT_USER_PROMPT = (
    "Inicia una campaña de red team contra el objetivo fijo. Trabaja por fases: "
    "fingerprinting, enumeración de rutas/artefactos y usuarios, credential access "
    "con la lista fija, acceso inicial y reporte. Usa las herramientas, narra con "
    "técnica, cita MITRE y no salgas del sandbox."
)

TOOLS = [
    {
        "name": "revisar_rutas",
        "description": "Enumera una lista fija de rutas y artefactos comunes (/robots.txt, /admin, /.env, /.git/config, /backup.sql, /api/users, /debug, /server-status, /metrics, /openapi.json, /docs) contra el objetivo fijo.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "revisar_headers",
        "description": "Hace fingerprinting HTTP: server, cabeceras de seguridad faltantes y superficie de la app.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "probar_login",
        "description": "Intenta el siguiente par de una lista fija de credenciales de prueba (spraying/guessing). Los parámetros usuario/clave son ignorados; nunca usa credenciales reales.",
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
        "description": "Registra un hallazgo, su impacto y la técnica MITRE asociada.",
        "input_schema": {
            "type": "object",
            "properties": {"resumen": {"type": "string"}},
            "required": ["resumen"],
        },
    },
]


def _credentials(success_at: int = 7) -> list[str]:
    settings = get_settings()
    wrong = [item for item in BASE_PASSWORDS if item != settings.demo_password]
    prefix = wrong[: max(success_at - 1, 0)]
    rest = [item for item in wrong if item not in prefix]
    return (prefix + [settings.demo_password] + rest)[:24]


def _sanitize(text: str, limit: int = 700) -> str:
    cleaned = clean_text(text)
    cleaned = cleaned.replace("**", "").replace("__", "").replace("`", "")
    cleaned = cleaned.replace("*", "")
    cleaned = re.sub(r"(?i)password\d+", "[credencial oculta]", cleaned)
    cleaned = re.sub(
        r"(?i)(credencial(?:es)?[^()]{0,40})\(([^()]{1,40})\)",
        r"\1([credencial oculta])",
        cleaned,
    )
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


async def _post_exploitation(
    client: httpx.AsyncClient, user: str, exposed_count: int
) -> None:
    try:
        admin = await client.get("/admin")
        admin_status = admin.status_code
    except httpx.HTTPError:
        admin_status = "sin respuesta"
    verdict = (
        "superficie administrativa comprometida"
        if admin_status == 200
        else "sin acceso administrativo"
    )
    await broadcast_line(
        "probe_path",
        f"[FASE 4 · POST-EXPLOTACIÓN] [T1083] GET /admin → HTTP {admin_status} · {verdict}.",
    )
    await broadcast_line(
        "recon",
        "[FASE 5 · REPORTING] [T1595/T1083/T1110/T1078] Campaña completada: "
        f"cuenta '{user}' comprometida; {exposed_count} rutas/artefactos expuestos; "
        "rate limit ausente; evidencia consolidada para el defensor.",
    )


async def _run_scripted() -> None:
    settings = get_settings()
    credentials = _credentials(success_at=12)
    spray = [
        (user, password) for user in SPRAY_USERS for password in SPRAY_PASSWORDS
    ]
    await broadcast_line(
        "recon",
        "[FASE 0 · BRIEFING] [OPSEC] GROWJAk inicia campaña de red team contra "
        "app-login-demo (loopback). Source 203.0.113.7. Sin acciones fuera del sandbox.",
    )

    async with _client() as client:
        try:
            root = await client.get("/")
        except httpx.HTTPError:
            await broadcast_line("recon", "GROWJAk detenido: el objetivo no responde.")
            return

        server = root.headers.get("server", "desconocido")
        content_type = root.headers.get("content-type", "desconocido")
        await broadcast_line(
            "recon",
            f"[FASE 1 · RECON] [T1595] Fingerprinting HTTP: status {root.status_code} · "
            f"server {server} · content-type {content_type}.",
        )
        missing = _missing_headers(root)
        if missing:
            await broadcast_line(
                "recon",
                "[FASE 1 · RECON] [T1592] Cabeceras de seguridad ausentes: "
                + ", ".join(missing)
                + ".",
            )
        else:
            await broadcast_line(
                "recon", "[FASE 1 · RECON] [T1592] No faltan las cabeceras revisadas."
            )

        try:
            options = await client.options("/login")
            allow = options.headers.get("allow", "no expuesto")
            await broadcast_line(
                "recon",
                f"[FASE 1 · RECON] [T1595] OPTIONS /login → HTTP {options.status_code} · "
                f"Allow: {allow}.",
            )
        except httpx.HTTPError:
            await broadcast_line(
                "recon", "[FASE 1 · RECON] [T1595] OPTIONS /login sin respuesta."
            )

        try:
            robots = await client.get("/robots.txt")
            if robots.status_code == 200:
                disallow = [
                    line.split(":", 1)[1].strip()
                    for line in robots.text.splitlines()
                    if line.lower().startswith("disallow:")
                ]
                revealed = ", ".join(disallow) if disallow else "sin rutas"
                await broadcast_line(
                    "recon",
                    f"[FASE 1 · RECON] [T1083] robots.txt expuesto; rutas reveladas: "
                    f"{revealed}.",
                )
            else:
                await broadcast_line(
                    "recon",
                    f"[FASE 1 · RECON] [T1083] robots.txt → HTTP {robots.status_code}.",
                )
        except httpx.HTTPError:
            await broadcast_line(
                "recon", "[FASE 1 · RECON] [T1083] robots.txt sin respuesta."
            )

        exposed: list[str] = []
        await broadcast_line(
            "recon",
            "[FASE 2 · DISCOVERY] [T1595] Iniciando enumeración de superficie y artefactos.",
        )
        for path in FIXED_PATHS:
            if path == "/robots.txt":
                continue
            try:
                response = await client.get(path)
            except httpx.HTTPError:
                await broadcast_line(
                    "probe_path",
                    f"[FASE 2 · DISCOVERY] [T1083] GET {path} → sin respuesta.",
                )
                continue

            status = response.status_code
            if status == 200:
                exposed.append(path)
                await broadcast_line(
                    "probe_path",
                    f"[FASE 2 · DISCOVERY] [T1083] GET {path} → HTTP 200 · EXPOSED.",
                )
            else:
                await broadcast_line(
                    "probe_path",
                    f"[FASE 2 · DISCOVERY] [T1083] GET {path} → HTTP {status}.",
                )

            if path == "/api/users" and status == 200:
                try:
                    users = response.json().get("users", [])
                    if users:
                        await broadcast_line(
                            "recon",
                            "[FASE 2 · DISCOVERY] [T1087] Usuarios enumerados: "
                            + ", ".join(str(item) for item in users[:10])
                            + ".",
                        )
                except Exception:
                    pass
            if path == "/backup.sql" and status == 200:
                await broadcast_line(
                    "recon",
                    "[FASE 2 · DISCOVERY] [T1552] backup.sql expuesto "
                    "(sintético, sin datos reales).",
                )
            if path == "/debug" and status == 200:
                await broadcast_line(
                    "recon",
                    "[FASE 2 · DISCOVERY] [T1592] traza de depuración expuesta.",
                )
            if path in ("/openapi.json", "/docs") and status == 200:
                await broadcast_line(
                    "recon",
                    "[FASE 2 · DISCOVERY] [T1592] documentación/esquema de API expuesto.",
                )
            if path == "/.env" and status == 200:
                await broadcast_line(
                    "recon",
                    "[FASE 2 · DISCOVERY] [T1552] .env expuesto; configuración "
                    "sintética de demo, sin secretos reales.",
                )
            if path == "/.git/config" and status == 200:
                await broadcast_line(
                    "recon",
                    "[FASE 2 · DISCOVERY] [T1592] metadatos del repositorio expuestos.",
                )
            if path == "/admin" and status == 200:
                await broadcast_line(
                    "recon",
                    "[FASE 2 · DISCOVERY] [T1083] panel administrativo accesible "
                    "sin autenticación.",
                )
            if path == "/server-status" and status == 200:
                await broadcast_line(
                    "recon",
                    "[FASE 2 · DISCOVERY] [T1592] server-status expuesto.",
                )
            if path == "/metrics" and status == 200:
                await broadcast_line(
                    "recon",
                    "[FASE 2 · DISCOVERY] [T1592] métricas operativas expuestas.",
                )
            await asyncio.sleep(0.12)

        await broadcast_line(
            "recon",
            f"[FASE 3 · CREDENTIAL ACCESS] [T1110.003] Password spraying: "
            f"{len(SPRAY_USERS)} usuarios × {len(SPRAY_PASSWORDS)} claves "
            f"({len(spray)} intentos, valores ocultos).",
        )
        for spray_index, (user, password) in enumerate(spray, start=1):
            try:
                response = await client.post(
                    "/login", data={"username": user, "password": password}
                )
            except httpx.HTTPError:
                await broadcast_line(
                    "recon", "GROWJAk detenido: error de conexión durante spraying."
                )
                return
            if _is_blocked(response):
                await broadcast_line(
                    "blocked",
                    "[FASE 3 · CREDENTIAL ACCESS] GROWJAk detenido: IP bloqueada "
                    f"por el defensor durante spraying ({spray_index}/{len(spray)}).",
                )
                return
            if response.status_code == 200:
                cookie_note = (
                    "cookie de sesión emitida (valor no mostrado)"
                    if response.cookies.get("demo_session")
                    else "sin cookie de sesión"
                )
                await broadcast_line(
                    "brute_force_success",
                    f"[FASE 4 · INITIAL ACCESS] [T1078] Spraying exitoso como "
                    f"'{user}' · {cookie_note}.",
                )
                await _post_exploitation(client, user, len(exposed))
                await broadcast_line(
                    "recon", "GROWJAk detenido: campaña de red team completada."
                )
                return
            await broadcast_line(
                "brute_force_attempt",
                f"[FASE 3 · CREDENTIAL ACCESS] [T1110.003] Spraying '{user}' "
                f"({spray_index}/{len(spray)}) · credencial rechazada.",
            )
            await asyncio.sleep(0.12)

        await broadcast_line(
            "recon",
            f"[FASE 3 · CREDENTIAL ACCESS] [T1110.001] Password guessing dirigido "
            f"contra '{settings.demo_user}' · secuencia fija de {len(credentials)} "
            "credenciales.",
        )
        for index, password in enumerate(credentials, start=1):
            try:
                response = await client.post(
                    "/login",
                    data={"username": settings.demo_user, "password": password},
                )
            except httpx.HTTPError:
                await broadcast_line(
                    "recon", "GROWJAk detenido: error de conexión con el objetivo."
                )
                return

            if _is_blocked(response):
                await broadcast_line(
                    "blocked",
                    "[FASE 3 · CREDENTIAL ACCESS] GROWJAk detenido: IP bloqueada "
                    f"por el defensor (intento {index}/{len(credentials)}).",
                )
                return

            if response.status_code == 200:
                cookie_note = (
                    "cookie de sesión emitida (valor no mostrado)"
                    if response.cookies.get("demo_session")
                    else "sin cookie de sesión"
                )
                await broadcast_line(
                    "brute_force_success",
                    f"[FASE 4 · INITIAL ACCESS] [T1078] Intento {index}/"
                    f"{len(credentials)}: acceso válido como '{settings.demo_user}' "
                    f"· {cookie_note}.",
                )
                await _post_exploitation(client, settings.demo_user, len(exposed))
                await broadcast_line(
                    "recon", "GROWJAk detenido: campaña de red team completada."
                )
                return

            await broadcast_line(
                "brute_force_attempt",
                f"[FASE 3 · CREDENTIAL ACCESS] [T1110.001] Intento {index}/"
                f"{len(credentials)} contra '{settings.demo_user}' · "
                "credencial rechazada.",
            )
            await asyncio.sleep(0.18)

    await broadcast_line(
        "recon", "GROWJAk detenido: campaña completada sin acceso."
    )


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
        server = response.headers.get("server", "desconocido")
        prefix = f"Fingerprinting: server {server}. "
        if missing:
            return ToolResult(
                prefix + "Cabeceras de seguridad ausentes: " + ", ".join(missing) + ".",
                action="recon",
            )
        return ToolResult(prefix + "No faltan las cabeceras revisadas.", action="recon")

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
                f"GROWJAk detenido: la IP fue bloqueada por el defensor "
                f"(intento {self.index}/{total}).",
                action="blocked",
                blocked=True,
            )
        if response.status_code == 200:
            cookie_note = (
                " cookie de sesión emitida (valor no mostrado)."
                if response.cookies.get("demo_session")
                else " sin cookie de sesión."
            )
            return ToolResult(
                f"Intento {self.index}/{total}: acceso concedido como "
                f"'{settings.demo_user}'.{cookie_note}",
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


async def _run_agentic_anthropic() -> None:
    settings = get_settings()
    if not settings.anthropic_api_key:
        await broadcast_line(
            "recon", "IA no configurada; ejecutando secuencia scripted de respaldo."
        )
        await _run_scripted()
        return

    from anthropic import AsyncAnthropic

    await broadcast_line(
        "recon", "GROWJAk · motor Anthropic iniciado. Objetivo fijo: app-login-demo."
    )
    client = AsyncAnthropic(api_key=settings.anthropic_api_key, timeout=25.0)
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": AGENT_USER_PROMPT}
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
                    await broadcast_line("recon", block.text[:320])
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
                await broadcast_line(
                    "recon",
                    "[FASE 5 · REPORTING] [T1078] Acceso válido confirmado; "
                    "evidencia de superficie expuesta reportada al defensor.",
                )
                await broadcast_line(
                    "recon", "GROWJAk detenido: campaña de red team completada."
                )
                return
            if finished:
                return

    await broadcast_line("recon", "GROWJAk detenido: límite de pasos alcanzado.")


def _openai_tools() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["input_schema"],
            },
        }
        for tool in TOOLS
    ]


async def _run_agentic_groq() -> None:
    settings = get_settings()
    await broadcast_line(
        "recon", "GROWJAk · motor Groq iniciado. Objetivo fijo: app-login-demo."
    )
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": AGENT_USER_PROMPT},
    ]
    tools = _openai_tools()

    async with _client() as http_client:
        toolbox = Toolbox(http_client)
        for step in range(settings.max_attack_steps):
            try:
                data = await groq_chat_completion(
                    messages,
                    tools=tools,
                    max_tokens=400,
                    temperature=0.3,
                    deadline_seconds=60.0,
                )
            except Exception as exc:
                logger.warning(
                    "GROWJAk Groq no respondió (%s)", type(exc).__name__
                )
                await broadcast_line(
                    "recon", "GROWJAk detenido: proveedor IA no disponible."
                )
                return

            content = extract_content(data)
            message = (data.get("choices") or [{}])[0].get("message") or {}
            raw_calls = message.get("tool_calls") or []
            usage = data.get("usage") or {}
            logger.info(
                "GROWJAk Groq paso %s · tool_calls=%s · total_tokens=%s",
                step + 1,
                len(raw_calls),
                usage.get("total_tokens"),
            )
            if content.strip():
                await broadcast_line("recon", content[:320])

            calls: list[tuple[str, str, Any]] = []
            assistant_message: dict[str, Any] = {
                "role": "assistant",
                "content": content or None,
            }
            if raw_calls:
                tool_calls_payload = []
                for index, call in enumerate(raw_calls):
                    function = call.get("function") or {}
                    call_id = call.get("id") or f"call_{step}_{index}"
                    name = function.get("name") or ""
                    arguments = function.get("arguments") or "{}"
                    calls.append((call_id, name, arguments))
                    tool_calls_payload.append(
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {"name": name, "arguments": arguments},
                        }
                    )
                assistant_message["tool_calls"] = tool_calls_payload

            messages.append(assistant_message)

            if not calls:
                messages.append(
                    {
                        "role": "user",
                        "content": "Continúa usando una de las herramientas disponibles.",
                    }
                )
                continue

            blocked = False
            success = False
            for call_id, name, raw_arguments in calls:
                try:
                    arguments = (
                        json.loads(raw_arguments)
                        if isinstance(raw_arguments, str)
                        else raw_arguments
                    )
                except (TypeError, json.JSONDecodeError):
                    arguments = {}
                if not isinstance(arguments, dict):
                    arguments = {}
                result = await toolbox.execute(name, arguments)
                await broadcast_line(result.action, result.summary)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": result.summary,
                    }
                )
                if result.blocked:
                    blocked = True
                if result.success:
                    success = True

            if blocked:
                return
            if success:
                await broadcast_line(
                    "recon",
                    "[FASE 5 · REPORTING] [T1078] Acceso válido confirmado; "
                    "evidencia de superficie expuesta reportada al defensor.",
                )
                await broadcast_line(
                    "recon", "GROWJAk detenido: campaña de red team completada."
                )
                return

    await broadcast_line("recon", "GROWJAk detenido: límite de pasos alcanzado.")


async def _run_agentic() -> None:
    provider = get_settings().active_llm_provider
    if provider == "groq":
        await _run_agentic_groq()
    elif provider == "anthropic":
        await _run_agentic_anthropic()
    else:
        await broadcast_line(
            "recon", "IA no configurada; ejecutando secuencia scripted de respaldo."
        )
        await _run_scripted()


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
                "recon", "GROWJAk detenido: tiempo máximo de ejecución excedido."
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("GROWJAk falló (%s)", type(exc).__name__)
            await broadcast_line(
                "recon",
                f"GROWJAk detenido: error inesperado ({type(exc).__name__}).",
            )
        finally:
            self._running = False

    async def _execute(self, mode: str) -> None:
        if mode == "agentic":
            await _run_agentic()
        else:
            await _run_scripted()
