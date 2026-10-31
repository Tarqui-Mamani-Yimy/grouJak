from __future__ import annotations

import asyncio
import json
import os

import httpx
import websockets

BACKEND = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")
DEMO = os.getenv("DEMO_APP_URL", "http://127.0.0.1:8080")
WS = os.getenv("WS_URL", "ws://127.0.0.1:8000/ws/live")
ATTACK_MODE = os.getenv("ATTACK_MODE", "scripted")
WAIT_SECONDS = float(os.getenv("WAIT_SECONDS", "45"))


async def main() -> None:
    messages: list[dict] = []
    finished = asyncio.Event()

    async with websockets.connect(WS) as socket:

        async def collect() -> None:
            async for raw in socket:
                message = json.loads(raw)
                messages.append(message)
                kind = message.get("type")
                if kind == "attacker_log":
                    line = message["line"]
                    print(f"  GROWJAk [{line['action']}] {line['detail']}")
                    if "GROWJAk detenido" in line["detail"]:
                        finished.set()
                elif kind == "alert_new":
                    alert = message["alert"]
                    print(f"  alerta #{alert['id']} {alert['rule']} count={alert['count']}")
                elif kind == "finding_new":
                    finding = message["finding"]
                    print(f"  hallazgo #{finding['id']} {finding['check']} {finding['status']}")
                elif kind == "blocked":
                    print(f"  bloqueo IP={message['ip']} alerta={message['alert_id']}")

        collector = asyncio.create_task(collect())

        async with httpx.AsyncClient(timeout=30.0) as client:
            print("[1] Escaneo")
            scan = await client.post(f"{BACKEND}/api/v1/scan")
            scan.raise_for_status()
            print(f"  {len(scan.json())} hallazgos")

            print(f"[2] Ataque {ATTACK_MODE}")
            start = await client.post(
                f"{BACKEND}/api/v1/attacker/run", json={"mode": ATTACK_MODE}
            )
            start.raise_for_status()

            await asyncio.wait_for(finished.wait(), timeout=WAIT_SECONDS)
            await asyncio.sleep(0.4)

            print("[3] Alerta y análisis")
            alerts = (await client.get(f"{BACKEND}/api/v1/alerts")).json()
            alert = alerts[-1]
            assert alert["rule"] == "success_after_failures", alert
            for _ in range(40):
                if alert.get("ai_result") is not None:
                    break
                await asyncio.sleep(0.25)
                alerts = (await client.get(f"{BACKEND}/api/v1/alerts")).json()
                alert = alerts[-1]
            assert alert["ai_result"] is not None, "La alerta no tiene ai_result"
            print(
                f"  alerta #{alert['id']} severity={alert['ai_result']['severity']} "
                f"confidence={alert['ai_result']['confidence']}"
            )
            assert alert["correlated_finding_ids"], "Sin hallazgos correlacionados"

            print("[4] Bloquear IP")
            blocked = await client.post(
                f"{BACKEND}/api/v1/block-ip",
                json={"ip": alert["source_ip"], "alert_id": alert["id"]},
            )
            blocked.raise_for_status()
            assert blocked.json() == {"blocked": True}

            print("[5] Login desde IP bloqueada")
            login = await client.post(
                f"{DEMO}/login",
                data={"username": "ana", "password": "incorrecta"},
                headers={"X-Demo-Client-IP": alert["source_ip"]},
            )
            assert login.status_code == 403, login.status_code
            print("  HTTP 403 correcto")

            print("[6] Segundo ataque tras bloqueo")
            finished.clear()
            start = await client.post(
                f"{BACKEND}/api/v1/attacker/run", json={"mode": "scripted"}
            )
            start.raise_for_status()
            await asyncio.wait_for(finished.wait(), timeout=20)
            await asyncio.sleep(0.2)
            blocked_lines = [
                message
                for message in messages
                if message.get("type") == "attacker_log"
                and message["line"]["action"] == "blocked"
            ]
            assert blocked_lines, "GROWJAk no detectó el bloqueo"
            print("  GROWJAk detenido por bloqueo")

            collector.cancel()

    print("\nSMOKE TEST OK")


if __name__ == "__main__":
    asyncio.run(main())
