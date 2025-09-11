#!/bin/sh
set -e

# Start FastAPI webhook
uvicorn main:app --host 0.0.0.0 --port 8000 &

# Give server a moment to boot
sleep 5

# Create or renew subscription (adjust script name if needed)
python scripts/create_subscription_users.py

# Keep container alive
wait -n
