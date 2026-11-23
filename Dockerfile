# Single-service image for hosts that run one web service (Render free tier):
# builds the React app, then serves it and the API from one FastAPI process on one origin.
# Docker Compose uses backend/Dockerfile and frontend/Dockerfile instead.

FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npx vite build

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SENTINEL_FRONTEND_DIR=/app/frontend-dist \
    SENTINEL_SAMPLE_DATA_DIR=/app/sample_data
WORKDIR /app/backend
COPY backend/requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt
COPY backend/ /app/backend/
COPY sample_data/ /app/sample_data/
COPY --from=frontend /build/dist /app/frontend-dist

RUN useradd --create-home --uid 10001 sentinel && chown -R sentinel /app
USER sentinel

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=5 \
  CMD python -c "import os,urllib.request,sys; p=os.environ.get('PORT','8000'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/api/v1/health/ready', timeout=4).status == 200 else 1)"
ENTRYPOINT ["sh", "/app/backend/docker-entrypoint.sh"]
