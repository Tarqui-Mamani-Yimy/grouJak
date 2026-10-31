#!/usr/bin/env bash
set -euo pipefail

curl -sS -m 15 -X POST http://127.0.0.1:8000/api/v1/demo/alert | python3 -m json.tool
