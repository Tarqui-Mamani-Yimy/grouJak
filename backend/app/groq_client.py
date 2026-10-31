from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from .config import get_settings

logger = logging.getLogger(__name__)


class GroqError(RuntimeError):
    pass


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    raw = response.headers.get("retry-after", "")
    try:
        return min(max(float(raw), 0.5), 20.0)
    except ValueError:
        return min(2.0**attempt, 8.0)


def extract_content(data: dict[str, Any]) -> str:
    choices = data.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    return message.get("content") or ""


async def groq_chat_completion(
    messages: list[dict[str, Any]],
    *,
    tools: list[dict[str, Any]] | None = None,
    max_tokens: int = 700,
    temperature: float = 0.2,
    deadline_seconds: float = 45.0,
) -> dict[str, Any]:
    settings = get_settings()
    if not settings.groq_enabled:
        raise GroqError("Groq no configurado")

    payload: dict[str, Any] = {
        "model": settings.groq_model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
        payload["parallel_tool_calls"] = False

    url = f"{settings.groq_base_url}/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.groq_api_key}",
        "Content-Type": "application/json",
    }
    started = time.monotonic()
    last_error: Exception | None = None

    for attempt in range(3):
        if time.monotonic() - started > deadline_seconds:
            break
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(30.0, connect=10.0)
            ) as client:
                response = await client.post(url, headers=headers, json=payload)
        except httpx.HTTPError as exc:
            last_error = exc
            if attempt < 2:
                await asyncio.sleep(min(2.0**attempt, 4.0))
                continue
            break

        if response.status_code == 429:
            delay = _retry_delay(response, attempt)
            logger.warning(
                "Groq 429 (intento %s/3); reintentando en %.1fs",
                attempt + 1,
                delay,
            )
            if attempt < 2 and time.monotonic() - started + delay <= deadline_seconds:
                await asyncio.sleep(delay)
                continue
            raise GroqError("Groq alcanzó el límite de peticiones")

        if response.status_code >= 500:
            last_error = GroqError(f"Groq HTTP {response.status_code}")
            logger.warning("Groq HTTP %s; reintentando", response.status_code)
            if attempt < 2:
                await asyncio.sleep(min(2.0**attempt, 4.0))
                continue
            raise last_error

        if response.status_code != 200:
            error_type = "desconocido"
            error_code = "desconocido"
            try:
                error = response.json().get("error") or {}
                error_type = str(error.get("type", "desconocido"))
                error_code = str(error.get("code", "desconocido"))
            except ValueError:
                pass
            logger.warning(
                "Groq HTTP %s · type=%s · code=%s",
                response.status_code,
                error_type,
                error_code,
            )
            raise GroqError(f"Groq HTTP {response.status_code}")

        try:
            return response.json()
        except ValueError as exc:
            raise GroqError("Groq devolvió una respuesta no JSON") from exc

    if last_error is not None:
        raise GroqError("Groq no respondió") from last_error
    raise GroqError("Groq excedió el tiempo de espera")
