#!/usr/bin/env bash
set -euo pipefail

# Kick off subscription creation in the background after the server is up.
( sleep 5; python scripts/create_subscription_users.py || echo "[warn] subscription script failed (non-fatal)" ) &

# Start FastAPI in the foreground so container stays alive
exec uvicorn main:app \
  --host 0.0.0.0 \
  --port "${WEBSITES_PORT:-8000}" \
  --proxy-headers \
  --forwarded-allow-ips="*"
