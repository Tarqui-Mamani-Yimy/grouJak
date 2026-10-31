from __future__ import annotations

import asyncio
import hmac
import logging
from contextlib import asynccontextmanager, suppress
from typing import Annotated

from fastapi import (
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware

from . import service, telegram
from .attacker import AttackerRunner
from .config import get_settings
from .scanner import ScannerError, run_scan
from .schemas import AttackerRunRequest, BlockRequest, EventBatch
from .store import get_db, init_db
from .ws import manager

logger = logging.getLogger(__name__)

API_KEY_HEADER = Header(alias="X-API-Key")


def authenticate(api_key: str | None) -> str:
    settings = get_settings()
    if not api_key or not hmac.compare_digest(api_key, settings.api_key):
        raise HTTPException(status_code=401, detail="API Key inválida")
    return settings.company_name


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Evita que httpx registre URLs con el token del bot de Telegram.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    settings = get_settings()
    init_db(settings.database_file)
    app.state.attacker = AttackerRunner()

    telegram_task: asyncio.Task | None = None
    if settings.telegram_enabled:
        telegram_task = asyncio.create_task(telegram.run_polling())
    else:
        logger.info("Telegram desactivado: faltan TELEGRAM_BOT_TOKEN o TELEGRAM_CHAT_ID")

    yield

    if telegram_task is not None:
        telegram_task.cancel()
        with suppress(asyncio.CancelledError):
            await telegram_task


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="Sentinel Demo API", version="1.0.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    @app.post("/api/v1/events")
    async def ingest_events(
        batch: EventBatch,
        x_api_key: Annotated[str | None, API_KEY_HEADER] = None,
    ) -> dict:
        company = authenticate(x_api_key)
        alerts = await service.ingest_events(batch.events, company)
        return {"alerts_created": [alert.model_dump(mode="json") for alert in alerts]}

    @app.get("/api/v1/alerts")
    async def list_alerts(
        since_id: Annotated[int | None, Query(ge=0)] = None,
    ) -> list[dict]:
        return [
            alert.model_dump(mode="json")
            for alert in get_db().list_alerts(since_id)
        ]

    @app.get("/api/v1/findings")
    async def list_findings() -> list[dict]:
        return [finding.model_dump(mode="json") for finding in get_db().list_findings()]

    @app.post("/api/v1/scan")
    async def scan() -> list[dict]:
        try:
            findings = await run_scan()
        except ScannerError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        for finding in findings:
            await manager.broadcast(
                {"type": "finding_new", "finding": finding.model_dump(mode="json")}
            )
        return [finding.model_dump(mode="json") for finding in findings]

    @app.post("/api/v1/block-ip")
    async def block_ip(request: BlockRequest) -> dict:
        try:
            await service.block_alert_ip(request.alert_id, request.ip)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"blocked": True}

    @app.post("/api/v1/attacker/run")
    async def run_attacker(body: AttackerRunRequest, request: Request) -> dict:
        runner: AttackerRunner = request.app.state.attacker
        if not runner.start(body.mode):
            raise HTTPException(status_code=409, detail="Ya hay un ataque en curso")
        return {
            "status": "started",
            "mode": body.mode,
            "target": settings.demo_host,
        }

    @app.post("/api/v1/demo/alert")
    async def demo_alert() -> dict:
        alert = await service.create_demo_alert()
        return alert.model_dump(mode="json")

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.websocket("/ws/live")
    async def websocket_live(websocket: WebSocket) -> None:
        await manager.connect(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            await manager.disconnect(websocket)

    return app


app = create_app()
