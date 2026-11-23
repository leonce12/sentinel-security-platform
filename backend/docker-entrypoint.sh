#!/bin/sh
# Apply database migrations, then start the API.
# PORT is set by hosts such as Render; SENTINEL_PORT or 8000 otherwise.
set -e
echo "Applying database migrations..."
alembic upgrade head
echo "Starting Sentinel API..."
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-${SENTINEL_PORT:-8000}}" \
  --proxy-headers --forwarded-allow-ips="*" --workers "${SENTINEL_WORKERS:-1}" --no-server-header
