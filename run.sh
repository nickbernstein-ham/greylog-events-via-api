#!/usr/bin/env bash
set -euo pipefail
test -e .venv/bin/activate || uv venv --python 3.12
source .venv/bin/activate
uv pip install -r requirements.txt
uv add --dev pytest
uv run --env-file .env pytest
uv run --env-file .env python app.py --stream Test --limit 1
