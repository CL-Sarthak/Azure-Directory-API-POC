#!/usr/bin/env bash
set -euo pipefail

# 1) start API
uvicorn app.main:app --host 0.0.0.0 --port 8000 &
APP_PID=$!

# 2) wait for readiness (local http check)
for i in {1..30}; do
  if curl -sf "http://127.0.0.1:8000/" >/dev/null; then break; fi
  sleep 1
done

# 3) optionally auto-subscribe (default on)
AUTO_SUBSCRIBE="${AUTO_SUBSCRIBE:-1}"
RENEW_EVERY="${RENEW_EVERY:-2700}"  # seconds (45 min)

if [ "$AUTO_SUBSCRIBE" = "1" ]; then
  echo "[startup] ensuring subscription…"
  python /app/scripts/create_subscription_users.py ensure || true

  # 4) background renewer (idempotent)
  (
    while true; do
      sleep "$RENEW_EVERY"
      echo "[renewer] ensuring subscription…"
      python /app/scripts/create_subscription_users.py ensure || true
    done
  ) &
fi

# 5) keep container running
wait "$APP_PID"
