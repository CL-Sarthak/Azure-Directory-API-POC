#!/usr/bin/env bash
set -euo pipefail
# (no migrations in this POC)
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
