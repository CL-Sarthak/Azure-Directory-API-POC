#!/bin/bash
set -euo pipefail

# start the api
uvicorn app.main:app --host 0.0.0.0 --port 8000 &
APP_PID=$!

# give it a second to boot
sleep 2

# (recommended) do NOT auto-create the subscription here; run it manually later
# python /app/scripts/create_subscription_users.py || true

# keep container running
wait "$APP_PID"
