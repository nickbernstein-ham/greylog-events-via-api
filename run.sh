source .venv/bin/activate
uv pip install -r requirements.txt
uv add --dev pytest
uv run --env-file pytest
uv run --env-file .env python app.py --stream Test --limit 1
