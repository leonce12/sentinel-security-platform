"""ASGI middleware: request body size limit and security headers.

Both are plain ASGI middleware (not BaseHTTPMiddleware) so they work on the raw byte stream
and add almost no overhead.
"""

import json

from app.core.config import get_settings

API_CSP = "default-src 'none'; frame-ancestors 'none'"
# The React app only loads its own scripts and styles. Recharts and Tailwind use inline style
# attributes, hence 'unsafe-inline' for styles only. No inline scripts are allowed.
SPA_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
           "connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; "
           "form-action 'self'")


class BodySizeLimitMiddleware:
    """Reject request bodies above a hard limit while they stream in.

    The upload route also checks the file size, but by then the framework has already received
    the whole body. This middleware stops oversized or endless bodies early, using the
    Content-Length header when present and counting bytes when it is not (chunked uploads).
    """

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            return await self._reject(send)

        received = 0
        response_started = False

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _TooLarge()
            return message

        async def tracking_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            if not response_started:
                await self._reject(send)

    async def _reject(self, send):
        body = json.dumps({"error": {"code": "payload_too_large", "message": "Request body is too large",
                                     "details": None}}).encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


class _TooLarge(Exception):
    pass


class SecurityHeadersMiddleware:
    """Security headers on every response. API responses are never cached and get a CSP that
    allows nothing; pages of the React app get a CSP that allows only same-origin resources."""

    def __init__(self, app):
        self.app = app
        settings = get_settings()
        self.api_prefix = settings.api_prefix
        self.hsts = settings.is_production

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        is_api = path.startswith(self.api_prefix)
        is_docs = path.endswith("/docs") or path.endswith("/openapi.json")

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                present = {k.lower() for k, _ in headers}

                def add(name: str, value: str):
                    if name.encode() not in present:
                        headers.append((name.encode(), value.encode()))

                add("x-content-type-options", "nosniff")
                add("x-frame-options", "DENY")
                add("referrer-policy", "no-referrer")
                add("permissions-policy", "camera=(), microphone=(), geolocation=()")
                add("cross-origin-opener-policy", "same-origin")
                if self.hsts:
                    add("strict-transport-security", "max-age=31536000; includeSubDomains")
                if is_api:
                    add("cache-control", "no-store")
                    if not is_docs:
                        add("content-security-policy", API_CSP)
                else:
                    add("content-security-policy", SPA_CSP)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)
