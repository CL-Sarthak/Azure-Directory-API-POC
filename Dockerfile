# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    WEBSITES_PORT=8000

WORKDIR /app

# Install certs (HTTPS), bash (for your script), and dos2unix (normalize line endings)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates bash dos2unix \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN python -m pip install --upgrade pip && python -m pip install -r requirements.txt

# Copy app code
COPY . .

# Normalize line endings and make the start script executable (do this as root)
RUN dos2unix /app/start.sh || true \
    && chmod +x /app/start.sh

# (Optional) drop privileges
RUN useradd -m appuser
USER appuser

EXPOSE 8000

# Run the start script directly; it should have `#!/usr/bin/env bash` at the top
ENTRYPOINT ["/app/start.sh"]
