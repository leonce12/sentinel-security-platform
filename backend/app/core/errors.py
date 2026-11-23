"""Consistent error responses.

Every error leaves the API as {"error": {"code": ..., "message": ..., "details": ...}}.
Unexpected exceptions are logged with a request ID and the client only sees a generic
message, so stack traces and internal details are never exposed.
"""

import logging
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger("sentinel.errors")


class AppError(Exception):
    """Raised by services for expected, user-facing failures."""

    def __init__(self, message: str, status_code: int = 400, code: str = "bad_request", details=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        self.details = details


class NotFound(AppError):
    def __init__(self, what: str):
        super().__init__(f"{what} not found", 404, "not_found")


class Conflict(AppError):
    def __init__(self, message: str):
        super().__init__(message, 409, "conflict")


def _body(code: str, message: str, details=None) -> dict:
    return {"error": {"code": code, "message": message, "details": details}}


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def app_error_handler(_request: Request, exc: AppError):
        return JSONResponse(_body(exc.code, exc.message, exc.details), status_code=exc.status_code)

    @app.exception_handler(HTTPException)
    async def http_error_handler(_request: Request, exc: HTTPException):
        code = {401: "unauthorized", 403: "forbidden", 404: "not_found", 429: "rate_limited"}.get(
            exc.status_code, "http_error"
        )
        return JSONResponse(
            _body(code, str(exc.detail)), status_code=exc.status_code, headers=getattr(exc, "headers", None)
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError):
        details = [
            {"field": ".".join(str(p) for p in err["loc"] if p != "body"), "message": err["msg"]}
            for err in exc.errors()
        ]
        return JSONResponse(_body("validation_error", "Request validation failed", details), status_code=422)

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception):
        request_id = uuid.uuid4().hex[:12]
        logger.exception("Unhandled error %s on %s %s", request_id, request.method, request.url.path)
        return JSONResponse(
            _body("internal_error", f"An internal error occurred. Reference: {request_id}"), status_code=500
        )
