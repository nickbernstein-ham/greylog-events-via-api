#!/usr/bin/env bash
set -euo pipefail

if [[ -f .env ]]; then
  ENV_ARGS=(--env-file .env)
else
  ENV_ARGS=()
fi

APP_FILE="${APP_FILE:-app.py}"
STREAM="${STREAM:-Test}"
LIMIT="${LIMIT:-1}"

uv sync --dev

uv run black .
uv run ruff check --fix .
uv run "${ENV_ARGS[@]}" pytest -q

uv run "${ENV_ARGS[@]}" python "$APP_FILE" --stream "$STREAM" --limit "$LIMIT"
