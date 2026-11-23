"""Sentinel API application factory."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect

from app.api.routes import alerts, auth, events, incidents, intel, platform, rules, users
from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.database.session import SessionLocal, engine
from app.services.demo import seed_reference_data

settings = get_settings()
logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("sentinel")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Migrations create the schema (alembic upgrade head). Here we only seed reference rows.
    if inspect(engine).has_table("roles"):
        with SessionLocal() as db:
            seed_reference_data(db)
    else:
        logger.warning("Database schema missing. Run 'alembic upgrade head' before using the API.")
    yield


app = FastAPI(
    title="Sentinel API",
    description="Defensive cybersecurity monitoring and threat detection platform.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=f"{settings.api_prefix}/docs",
    openapi_url=f"{settings.api_prefix}/openapi.json",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,  # explicit list, never "*", because cookies are used
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if not request.url.path.endswith("/docs"):
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


register_error_handlers(app)

for module in (auth, users, events, alerts, incidents, rules, intel, platform):
    app.include_router(module.router, prefix=settings.api_prefix)
