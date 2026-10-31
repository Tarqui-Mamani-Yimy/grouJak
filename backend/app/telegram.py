from __future__ import annotations

import asyncio
import json
import logging

import httpx

from .config import get_settings
from .schemas import Alert, clean_text
from .store import get_db

logger = logging.getLogger(__name__)

RULE_LABELS = {
    "brute_force": "Fuerza bruta",
    "success_after_failures": "Éxito tras fallos",
}


def _line(value: str, limit: int = 200) -> str:
    return clean_text(value)[:limit]


def build_message(alert: Alert) -> str:
    result = alert.ai_result
    severity = result.severity.upper() if result else "HIGH"
    explanation = _line(result.explanation, 700) if result else "Alerta generada por reglas."
    cause = _line(result.probable_cause, 500) if result else "Requiere revisión."
    confidence = f"{result.confidence * 100:.0f}%" if result else "n/d"
    actions = result.recommended_actions if result else [f"Bloquear la IP {alert.source_ip}"]

    lines = [
        f"🛡️ ALERTA {severity} · {RULE_LABELS.get(alert.rule, alert.rule)}",
        f"Activo: {_line(alert.host, 80)}",
        f"IP: {alert.source_ip}",
        f"Usuario: {_line(alert.user, 80)}",
        f"Intentos: {alert.count} en {alert.window_seconds} s",
        "",
        f"Explicación: {explanation}",
        f"Causa probable: {cause}",
        "",
        "Plan de corrección:",
    ]
    for index, action in enumerate(actions, start=1):
        lines.append(f"{index}. {_line(action, 300)}")
    lines.extend(["", f"Confianza IA: {confidence}"])
    text = "\n".join(lines)
    return text[:4000]


async def notify_alert(alert: Alert) -> int | None:
    settings = get_settings()
    if not settings.telegram_enabled:
        return None

    url = f"https://api.telegram.org/bot{settings.telegram_bot_token}"
    keyboard = (
        {"inline_keyboard": []}
        if alert.blocked
        else {"inline_keyboard": [[{"text": "Bloquear IP", "callback_data": f"block:{alert.id}"}]]}
    )
    text = build_message(alert)
    existing_id = get_db().get_telegram_message_id(alert.id)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            if existing_id:
                response = await client.post(
                    f"{url}/editMessageText",
                    json={
                        "chat_id": settings.telegram_chat_id,
                        "message_id": existing_id,
                        "text": text,
                        "reply_markup": keyboard,
                    },
                )
                if response.status_code == 200 and response.json().get("ok"):
                    return existing_id
                logger.warning(
                    "No se pudo editar el mensaje de Telegram (%s)", response.status_code
                )
                return existing_id

            response = await client.post(
                f"{url}/sendMessage",
                json={
                    "chat_id": settings.telegram_chat_id,
                    "text": text,
                    "reply_markup": keyboard,
                },
            )
            data = response.json()
            if response.status_code == 200 and data.get("ok"):
                return int(data["result"]["message_id"])
            logger.warning("No se pudo enviar el mensaje de Telegram (%s)", response.status_code)
            return None
    except Exception as exc:
        logger.warning("Telegram no disponible (%s)", type(exc).__name__)
        return None


async def _answer_callback(client: httpx.AsyncClient, base: str, callback_id: str, text: str) -> None:
    try:
        await client.post(
            f"{base}/answerCallbackQuery",
            json={"callback_query_id": callback_id, "text": text},
        )
    except Exception:
        pass


async def _remove_button(client: httpx.AsyncClient, base: str, chat_id: str, message_id: int) -> None:
    try:
        await client.post(
            f"{base}/editMessageReplyMarkup",
            json={
                "chat_id": chat_id,
                "message_id": message_id,
                "reply_markup": {"inline_keyboard": []},
            },
        )
    except Exception:
        pass


async def run_polling() -> None:
    settings = get_settings()
    if not settings.telegram_enabled:
        return

    base = f"https://api.telegram.org/bot{settings.telegram_bot_token}"
    offset: int | None = None
    logger.info("Telegram long polling iniciado")

    while True:
        try:
            async with httpx.AsyncClient(timeout=40.0) as client:
                params: dict = {"timeout": 25, "allowed_updates": json.dumps(["callback_query"])}
                if offset is not None:
                    params["offset"] = offset
                response = await client.get(f"{base}/getUpdates", params=params)
                data = response.json()
                if not data.get("ok"):
                    logger.warning("Telegram getUpdates devolvió error")
                    await asyncio.sleep(3)
                    continue

                for update in data.get("result", []):
                    offset = int(update["update_id"]) + 1
                    callback = update.get("callback_query")
                    if not callback:
                        continue

                    callback_id = callback.get("id", "")
                    message = callback.get("message") or {}
                    chat_id = str((message.get("chat") or {}).get("id", ""))
                    if chat_id != str(settings.telegram_chat_id):
                        await _answer_callback(client, base, callback_id, "No autorizado")
                        continue

                    payload = str(callback.get("data", ""))
                    if not payload.startswith("block:"):
                        await _answer_callback(client, base, callback_id, "Acción desconocida")
                        continue
                    try:
                        alert_id = int(payload.split(":", 1)[1])
                    except ValueError:
                        await _answer_callback(client, base, callback_id, "Alerta inválida")
                        continue

                    alert = get_db().get_alert(alert_id)
                    if alert is None:
                        await _answer_callback(client, base, callback_id, "Alerta no encontrada")
                        continue

                    blocked = False
                    try:
                        async with httpx.AsyncClient(timeout=10.0) as backend:
                            result = await backend.post(
                                f"{settings.backend_url}/api/v1/block-ip",
                                json={"ip": alert.source_ip, "alert_id": alert.id},
                            )
                            blocked = result.status_code == 200
                    except Exception:
                        blocked = False

                    await _answer_callback(
                        client,
                        base,
                        callback_id,
                        "IP bloqueada" if blocked else "No se pudo bloquear la IP",
                    )
                    message_id = message.get("message_id")
                    if blocked and message_id:
                        await _remove_button(client, base, chat_id, int(message_id))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Error en long polling de Telegram (%s)", type(exc).__name__)
            await asyncio.sleep(3)
