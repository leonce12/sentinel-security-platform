# Sentinel API. Build context is the repository root (see docker-compose.yml) so the
# synthetic sample data can be included for the demo loader.
FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SENTINEL_SAMPLE_DATA_DIR=/app/sample_data

WORKDIR /app/backend
COPY backend/requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY backend/ /app/backend/
COPY sample_data/ /app/sample_data/

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 sentinel && chown -R sentinel /app
USER sentinel

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/ready', timeout=4).status == 200 else 1)"

ENTRYPOINT ["sh", "/app/backend/docker-entrypoint.sh"]
