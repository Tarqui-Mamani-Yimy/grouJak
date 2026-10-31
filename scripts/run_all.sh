#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -x .venv/bin/python ]; then
  echo "Falta .venv. Ejecuta ./scripts/install.sh primero."
  exit 1
fi

if [ ! -d frontend/node_modules ]; then
  echo "Faltan dependencias del panel. Ejecuta ./scripts/install.sh primero."
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Creado .env desde .env.example"
fi

mkdir -p data
PIDS=()
cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

.venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 &
PIDS+=($!)

.venv/bin/uvicorn demo_app.main:app --host 127.0.0.1 --port 8080 &
PIDS+=($!)

(
  cd frontend
  exec node node_modules/vite/bin/vite.js --host 127.0.0.1
) &
PIDS+=($!)

cat <<'EOF'

Sentinel demo en marcha
  Panel:        http://127.0.0.1:5173
  API:          http://127.0.0.1:8000/docs
  App de demo:  http://127.0.0.1:8080

Ctrl+C detiene los tres procesos.
EOF

wait
