# Sentinel — demo de detección y respuesta con IA

Sistema demostrable de punta a punta para una sola pyme: app de login deliberadamente
vulnerable, backend que escanea, detecta ataques por reglas, correlaciona hallazgos y usa
**Groq Free** (`openai/gpt-oss-120b`) para explicar, priorizar y proponer un plan de
corrección. El agente ofensivo se llama **GROWJAk**; el defensor es el SOC. La alerta se
notifica por Telegram con un botón para bloquear la IP y se publica en vivo en un panel React
con dos terminales.

Todo el tráfico ofensivo apunta **solo** a la app de demo local. El objetivo está fijado en
el backend y validado como loopback; nunca se acepta un host desde el cliente, el modelo o
el frontend.

## Alcance congelado

- SQLite local, sin Docker ni Postgres.
- `POST /api/v1/events` con `X-API-Key` fija; una sola empresa.
- Dos reglas: fuerza bruta y éxito tras fallos.
- Escáner con cuatro chequeos fijos.
- **GROWJAk**: agente atacante con menú de herramientas acotado (scripted y agéntico con tool calling).
- IA defensora con salida JSON validada y texto de respaldo.
- Telegram con long polling y botón inline **Bloquear IP**.
- Panel React de dos columnas, estética de terminal y WebSocket.

Fuera de alcance: multiempresa, routers/syslog, WhatsApp, 2FA real, estados complejos,
login del panel, botón “Fue yo”, gráficos y escaneo de redes.

## Arquitectura

```
[GROWJAk] --ataca--> [App de login demo :8080] --POST /events--> [Backend FastAPI :8000]
                                                          |-- Reglas de detección
                                                          |-- Escáner (4 chequeos)
                                                          |-- Correlación alerta + findings
                                                          |-- IA defensora (Groq Free) --> JSON validado
                                                          |-- SQLite (events, findings, alerts, blocked_ips)
                                                          |-- Telegram (alerta + botón Bloquear IP)
                                                          |-- WebSocket /ws/live --> [Panel React :5173]
```

El contrato de datos de la sección 3 está implementado literalmente en
`backend/app/schemas.py`: `Event`, `EventBatch`, `Finding`, `Alert`, `AIResult` y
`AttackerLogLine`. Todos los timestamps viajan y se guardan en UTC con sufijo `Z`.

## Requisitos

- Python 3.11 o superior (probado con 3.14).
- Node.js 20 o superior y npm.
- Sin Docker.

## Inicio rápido

```bash
cp .env.example .env       # si aún no existe
./scripts/install.sh
./scripts/run_all.sh
```

Servicios:

- Panel: http://127.0.0.1:5173
- API y documentación: http://127.0.0.1:8000/docs
- App de login vulnerable: http://127.0.0.1:8080

`run_all.sh` mantiene los tres procesos en primer plano y los detiene juntos con `Ctrl+C`.
Todos los servidores escuchan en loopback (`127.0.0.1`).

## Configuración

Copia `.env.example` a `.env`. Variables principales:

| Variable | Uso |
| --- | --- |
| `API_KEY` | Clave fija que usa la app de login para `POST /events`. |
| `COMPANY_NAME` | Empresa deducida de la clave; no viaja en el body. |
| `DATABASE_PATH` | Ruta SQLite local. Por defecto `./data/sentinel.db`. |
| `DEMO_APP_URL` | Objetivo fijo del escáner y de GROWJAk. Debe ser loopback. |
| `DEMO_HOST` | Nombre del activo usado en eventos, findings y alertas. |
| `DEMO_USER`, `DEMO_PASSWORD` | Credenciales ficticias solo de la demo. No se muestran en el panel ni en logs. |
| `BRUTE_FORCE_THRESHOLD`, `BRUTE_FORCE_WINDOW_SECONDS` | Regla 1. En demo: 5 fallos en 60 s. |
| `ALERT_DEDUP_SECONDS` | Ventana de deduplicación por `(source_ip, host)`. Por defecto 300 s. |
| `LLM_PROVIDER` | `groq` (principal) o `anthropic` (opcional). |
| `GROQ_API_KEY` | Clave gratuita de Groq. Si falta o falla, se usa el texto de respaldo. |
| `GROQ_MODEL` | Modelo free; por defecto `openai/gpt-oss-120b`. |
| `GROQ_BASE_URL` | Endpoint OpenAI-compatible de Groq. |
| `ANTHROPIC_API_KEY`, `CLAUDE_MODEL` | Proveedor opcional de respaldo. |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Si faltan, Telegram queda desactivado sin romper el flujo. |
| `MAX_ATTACK_STEPS` | Tope duro de pasos del agente agéntico. |
| `ATTACKER_TIMEOUT_SECONDS` | Timeout total del ataque. |

La app de demo y el backend comparten la misma base SQLite para que el login consulte las
IPs bloqueadas en cada intento. La app demo acepta `X-Demo-Client-IP` únicamente desde
loopback para simular una IP externa (203.0.113.7); es un detalle de la demo, no un objetivo
configurable. Ejecuta un solo worker de uvicorn: WebSocket, locks y long polling viven en
memoria del proceso.

## IA: Groq Free y respaldo

La IA principal es **Groq Free** con `openai/gpt-oss-120b`, vía API compatible con OpenAI.
El plan Free documentado permite 30 RPM, 1 000 RPD, 8 000 TPM y 200 000 TPD; los límites
pueden cambiar, revísalos en Groq Console. El cliente reintenta con `Retry-After` si recibe
429. Si la clave falta, la API falla, tarda o el JSON no valida, se usa la plantilla
determinista.

La IA defensora se llama **solo cuando nace una alerta nueva o escala a éxito tras fallos**,
nunca por cada evento. Recibe un JSON acotado con la alerta y hasta cinco hallazgos
correlacionados. `user`, `host` y el resto de campos no confiables van delimitados con un
nonce y el prompt de sistema aclara que son datos, no instrucciones. El payload distingue
explícitamente `failed_attempts` de `successful_login` para evitar ambigüedades.

La respuesta se parsea y valida con Pydantic (`AIResult`). La detección y el bloqueo nunca
dependen de la IA. Si la regla es `success_after_failures`, la severidad mínima se fuerza a
`high` antes de publicar la alerta.

GROWJAk agéntico usa tool calling con herramientas fijas (`revisar_rutas`,
`revisar_headers`, `probar_login`, `reportar_hallazgo`) en formato OpenAI. No recibe un
objetivo como parámetro, no ejecuta código libre, usa una lista fija de credenciales de
prueba y tiene `MAX_ATTACK_STEPS` más timeout. Sin `GROQ_API_KEY` ni `ANTHROPIC_API_KEY`, cae
al modo scripted con un aviso. GROWJAk scripted es el modo recomendado para la demo porque
no consume tokens; el agéntico es opcional y puede encontrar el límite de TPM del plan free.

## Telegram

1. Crea un bot con BotFather y copia el token en `TELEGRAM_BOT_TOKEN`.
2. Obtén el chat destino y colócalo en `TELEGRAM_CHAT_ID`.
3. Inicia el backend: el long polling arranca solo, sin webhook ni ngrok.

El mensaje incluye severidad, clasificación MITRE, explicación, causa probable, plan de
corrección y confianza. El botón inline llama a `POST /api/v1/block-ip`. La deduplicación evita
un mensaje por evento: las actualizaciones de conteo no renotifican y una escalada edita el
mismo mensaje.

## Campaña de GROWJAk (sandbox)

GROWJAk ejecuta una campaña scripted con un kill chain acotado y profesional contra la app
demo:

1. Briefing y OPSEC: objetivo fijo, loopback y sin acciones fuera del sandbox.
2. Fingerprinting: server, cabeceras, métodos y `robots.txt` (T1595/T1592).
3. Discovery: enumeración de rutas y artefactos sintéticos (`/admin`, `/.env`,
   `/.git/config`, `/backup.sql`, `/api/users`, `/debug`, `/server-status`, `/metrics`,
   `/openapi.json`, `/docs`) y usuarios (T1083/T1087/T1552).
4. Credential access: password spraying sobre usuarios enumerados y password guessing con
   una secuencia fija de credenciales de prueba (T1110).
5. Acceso y post-explotación: cookie de sesión de demo, acceso a `/admin` y evidencia
   consolidada (T1078/T1083).
6. Reporting: resumen con técnicas MITRE y estado de la campaña.

La app demo contiene **artefactos sintéticos** expuestos para la simulación. No hay datos,
credenciales ni secretos reales. GROWJAk no recibe un objetivo del cliente, del modelo ni del
frontend; el host sigue fijo en el backend. El panel muestra fases, intentos, rutas, técnicas
MITRE y un resumen de campaña.

## Guion de demo (3 minutos)

1. **Problema (15 s).** “Una pyme tiene un login expuesto y nadie mira los logs.”
2. **Escaneo (20 s).** Pulsa `Escanear`. Aparecen cuatro hallazgos; destaca
   “Sin rate limit”, el que se explotará en vivo.
3. **Ataque (45 s).** Pulsa `Atacar (scripted)`. La terminal izquierda muestra las fases
   de red team, fingerprinting, enumeración, spraying, guessing y post-explotación, con
   técnicas MITRE. A los cinco fallos nace la alerta; el éxito posterior la escala a
   “Éxito tras fallos”.
4. **Defensa (45 s).** La terminal derecha muestra severidad, clasificación MITRE,
   explicación de Groq, plan priorizado, hallazgos correlacionados y el aviso de
   aprobación humana. Si Telegram está configurado, llega el mensaje con el botón
   `Bloquear IP`.
5. **Decisión humana (20 s).** Pulsa `Bloquear IP` (panel o Telegram). Los hallazgos pasan
   a mitigados y la IP queda bloqueada.
6. **Prueba del bloqueo (15 s).** Pulsa `Atacar (scripted)` de nuevo: la terminal muestra
   “IP bloqueada por el defensor”.
7. **Cierre (10 s).** Reglas deterministas detectan, la IA explica y prioriza, el humano
   aprueba el bloqueo. Menciona objetivo fijo, sin credenciales en pantalla, salida de IA
   validada, deduplicación y timeout de GROWJAk.

Plan B si el ataque en vivo no dispara: pulsa `Alerta demo` o ejecuta
`./scripts/simulate_alert.sh`. Inserta una alerta de ejemplo, correlaciona hallazgos y
dispara el mismo flujo de IA/Telegram/panel.

## API

| Método y ruta | Descripción |
| --- | --- |
| `POST /api/v1/events` | Ingesta `EventBatch`; requiere `X-API-Key`. Devuelve `{"alerts_created": [...]}`. |
| `GET /api/v1/alerts?since_id=` | Alertas para el panel. |
| `GET /api/v1/findings` | Hallazgos del escáner. |
| `POST /api/v1/scan` | Ejecuta los cuatro chequeos contra `DEMO_APP_URL`. |
| `POST /api/v1/block-ip` | Body `{"ip": str, "alert_id": int}`; devuelve `{"blocked": true}`. |
| `POST /api/v1/attacker/run` | Body `{"mode": "scripted" | "agentic"}`; solo apunta al host fijo. |
| `WS /ws/live` | Canal único con eventos `alert_new`, `finding_new`, `attacker_log`, `blocked`. |
| `POST /api/v1/demo/alert` | Alerta de ejemplo para el plan B de la demo. |

La clave se deduce del header para asignar la empresa; el body con `company` se rechaza con
422. Tampoco se aceptan campos extra como `password`.

## Reglas y deduplicación

- **Fuerza bruta:** `N` o más `login_failed` desde la misma `source_ip` y `host` en `W`
  segundos. Demo: `N=5`, `W=60`.
- **Éxito tras fallos:** si aparece un `login_success` del mismo usuario o la misma IP
  después de disparar la regla 1, la alerta existente escala a `success_after_failures`.
- **Deduplicación:** una alerta abierta por `(source_ip, host)` en los últimos 300 s no crea
  otra fila; actualiza el conteo. Una escalada reutiliza la misma alerta y el mismo mensaje
  de Telegram.
- **Bloqueo:** agrega la IP a `blocked_ips`, marca la alerta como bloqueada y mitiga los
  findings correlacionados.

## Escáner

Solo contra `DEMO_APP_URL` (loopback validado, nunca un parámetro del cliente):

1. Cabeceras de seguridad ausentes (`Strict-Transport-Security`, `X-Frame-Options`,
   `Content-Security-Policy`) → `medium`.
2. Rutas expuestas (`/.env`, `/.git/config`, `/admin` con HTTP 200) → `high`.
3. Sin HTTPS forzado → `medium`.
4. Login sin límite: 8 intentos fallidos sin 429, bloqueo ni retraso → `high`.

Los intentos del escáner usan un header interno y no generan eventos, para no contaminar el
flujo de ataque de la demo.

## Guardrails implementados

- Objetivo de escáner y de GROWJAk fijo en backend y validado como loopback.
- El endpoint `/attacker/run` no acepta `target`; el schema lo rechaza.
- Contraseñas fuera de eventos, logs, panel, prompts de IA y mensajes de Telegram.
- Credenciales de prueba ficticias y lista fija; GROWJAk no elige objetivo.
- `MAX_ATTACK_STEPS` y timeout; toda salida termina con “GROWJAk detenido”.
- `company` nunca viaja en el body; se deduce de la API Key.
- IA con JSON validado por Pydantic y plantilla de respaldo.
- Detección y bloqueo deterministas, independientes de la IA.
- Panel sin credenciales visibles y sin login (alcance congelado).
- Campaña ofensiva limitada al sandbox: sin objetivo externo, sin exfiltración real y con
  artefactos/credenciales sintéticas.
- Servidores en `127.0.0.1`; la app demo es intencionalmente vulnerable, no la publiques.

## Pruebas

```bash
.venv/bin/python -m pytest -q
cd frontend && npm run build
```

Con backend y app demo en marcha y una base limpia:

```bash
.venv/bin/python scripts/smoke_test.py
```

El smoke test escanea, ataca, espera la alerta, verifica el `ai_result`, bloquea la IP y lanza
un segundo ataque para comprobar el bloqueo. Como bloquea la IP, para repetirlo hay que
reiniciar con base limpia:

```bash
# detén los servicios y luego:
rm -f data/sentinel.db data/sentinel.db-wal data/sentinel.db-shm
```

La verificación de UI se hizo con Chrome headless sobre el flujo real: escanear → atacar →
alerta con IA → bloquear → segundo ataque detenido, sin errores de consola.

La integración con Groq se verificó en vivo con `openai/gpt-oss-120b`: la defensora devolvió
JSON validado y GROWJAk agéntico ejecutó tool calling con reintentos ante 429 del plan free.
La campaña scripted y el panel red team/SOC se verificaron con la UI real. La entrega por
Telegram se verificó con un mensaje real con botón inline. Las claves viven solo en `.env`
(ignorado por Git) y nunca se incluyen en logs, panel, prompts o commits. Sin claves
externas, la defensa usa la plantilla y GROWJAk cae al modo scripted.

## Estructura

```
backend/app/
  config.py        configuración y validación de loopback
  schemas.py       contrato de datos UTC/Z
  store.py         SQLite: events, findings, alerts, blocked_ips
  rules.py         reglas puras y testeables
  service.py       ingesta, deduplicación, escalada y publicación
  scanner.py       cuatro chequeos fijos
  groq_client.py   cliente OpenAI-compatible, retry 429 y extracción de respuestas
  ai.py            Groq/Anthropic, validación Pydantic y plantilla de respaldo
  telegram.py      long polling, botón inline y edición
  attacker.py      scripted + tool calling acotado
  processor.py     correlación → IA → guardado → Telegram → WS
  main.py          endpoints y WebSocket
demo_app/main.py   app de login vulnerable (solo local)
frontend/          panel React + Vite, dos terminales y reconexión WS
scripts/           instalación, arranque, alerta demo y smoke test
backend/tests/     reglas, API, IA y sanitización
```

## Checklist de presentación

- [x] Contrato de datos de la sección 3 implementado sin cambios.
- [x] Integración backend + demo + panel verificada de punta a punta.
- [ ] Video del flujo completo (paso manual del equipo).
- [x] Botón/comando de alerta de ejemplo (`Alerta demo` / `scripts/simulate_alert.sh`).
- [x] Guion de 3 minutos y mención de guardrails.
- [x] Campaña por fases con MITRE y panel red team/SOC.
- [x] Sin contraseñas visibles en panel, logs o mensajes.
- [x] Claves de Groq/Telegram fuera de Git (solo en `.env` local).

La demo no debe exponerse fuera de `127.0.0.1`.
