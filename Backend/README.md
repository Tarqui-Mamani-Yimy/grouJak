# Grok Backend

Initial backend scaffold built with FastAPI.

## Requirements

- Python 3.11 or newer

## Setup

```bash
cd Backend
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

On Windows PowerShell, activate the environment with `.venv\\Scripts\\Activate.ps1`.

## Run

```bash
uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`; interactive API documentation is at `/docs`.
The health check is `GET /health`.

## Test

```bash
pytest
```
