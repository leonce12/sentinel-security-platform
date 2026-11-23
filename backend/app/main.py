"""Sentinel API application factory."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect

from app.api.routes import alerts, auth, events, incidents, intel, platform, rules, users
from app.api.spa import mount_frontend
from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.core.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from app.database.session import SessionLocal, engine
from app.services.bootstrap import run_startup_tasks
from app.services.demo import seed_reference_data

settings = get_settings()
logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("sentinel")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Migrations create the schema (alembic upgrade head). Here we seed reference rows and run
    # the optional startup tasks (first administrator, demo account, demo dataset).
    if inspect(engine).has_table("roles"):
        with SessionLocal() as db:
            seed_reference_data(db)
        run_startup_tasks()
    else:
        logger.warning("Database schema missing. Run 'alembic upgrade head' before using the API.")
    if settings.is_production and not settings.cookie_secure:
        logger.warning("SENTINEL_COOKIE_SECURE is false in production: serve Sentinel over HTTPS and enable it.")
    yield


app = FastAPI(
    title="Sentinel API",
    description="Defensive cybersecurity monitoring and threat detection platform.",
    version="1.1.0",
    lifespan=lifespan,
    # Interactive API docs are off in production unless SENTINEL_EXPOSE_API_DOCS=true.
    docs_url=f"{settings.api_prefix}/docs" if settings.api_docs_enabled else None,
    openapi_url=f"{settings.api_prefix}/openapi.json" if settings.api_docs_enabled else None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,  # explicit list, never "*", because cookies are used
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)

register_error_handlers(app)

for module in (auth, users, events, alerts, incidents, rules, intel, platform):
    app.include_router(module.router, prefix=settings.api_prefix)

# Must be registered last: its catch-all route serves the React app for every other path.
if settings.frontend_dir:
    if mount_frontend(app, settings.frontend_dir, settings.api_prefix):
        logger.info("Serving the web interface from %s", settings.frontend_dir)
    else:
        logger.warning("SENTINEL_FRONTEND_DIR=%s has no index.html; web interface not served", settings.frontend_dir)
