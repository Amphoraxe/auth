"""
CSRF Protection - Token generation and validation.
"""

import secrets
from urllib.parse import parse_qs

from fastapi import Request, HTTPException
from starlette.types import ASGIApp, Receive, Scope, Send, Message

from app.logging_config import log_security, get_logger

logger = get_logger(__name__)

CSRF_TOKEN_KEY = "_csrf_token"

# Routes exempt from CSRF (JSON API endpoints)
CSRF_EXEMPT_PATHS = [
    "/api/",
    "/health",
]


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def get_csrf_token(request: Request) -> str:
    token = request.session.get(CSRF_TOKEN_KEY)
    if not token:
        token = generate_csrf_token()
        request.session[CSRF_TOKEN_KEY] = token
    return token


def validate_csrf_token(request: Request, token: str) -> bool:
    session_token = request.session.get(CSRF_TOKEN_KEY)
    if not session_token or not token:
        return False
    return secrets.compare_digest(session_token, token)


class CSRFMiddleware:
    """ASGI middleware for CSRF protection on form submissions."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive, send)

        if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
            await self.app(scope, receive, send)
            return

        path = request.url.path
        if any(path.startswith(exempt) for exempt in CSRF_EXEMPT_PATHS):
            await self.app(scope, receive, send)
            return

        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            await self.app(scope, receive, send)
            return

        if "application/x-www-form-urlencoded" in content_type:
            body_chunks = []
            while True:
                message = await receive()
                body_chunks.append(message.get("body", b""))
                if not message.get("more_body", False):
                    break

            body = b"".join(body_chunks)

            try:
                form_data = parse_qs(body.decode("utf-8"))
                submitted_token = form_data.get("csrf_token", [""])[0]
            except Exception:
                submitted_token = ""

            if not submitted_token:
                submitted_token = request.headers.get("X-CSRF-Token", "")

            if not validate_csrf_token(request, submitted_token):
                client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or \
                            (request.client.host if request.client else "unknown")
                log_security("CSRF_VALIDATION_FAILED", f"Invalid CSRF token on {path}",
                             ip_address=client_ip)
                await send({
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [(b"content-type", b"text/plain")],
                })
                await send({
                    "type": "http.response.body",
                    "body": b"CSRF validation failed",
                })
                return

            async def receive_wrapper() -> Message:
                return {"type": "http.request", "body": body, "more_body": False}

            await self.app(scope, receive_wrapper, send)
            return

        await self.app(scope, receive, send)
