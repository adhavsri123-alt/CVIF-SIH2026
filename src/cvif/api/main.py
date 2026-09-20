"""CVIF REST API Application Factory (Phase 10).

Creates the FastAPI application with:
- Lifespan context manager for RuntimeContext initialization/teardown
- Centralized exception handlers (Threat CT-12 / T-10-5 stack trace suppression)
- Request-ID correlation middleware
- All v1 route registrations under /api/v1 prefix
- CORS middleware (configurable, disabled by default)
- OpenAPI documentation control (disabled by default for air-gap compliance)
"""

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from cvif.api.error_handler import setup_exception_handlers
from cvif.api.frontend import (
    FrontendSecurityHeadersMiddleware,
    get_frontend_dist_dir,
    mount_frontend,
)
from cvif.api.routes import audit, assess, datasets, evidence, health, models, provenance, shift
from cvif.cli.commands.common import RuntimeContext
from cvif.cli.commands.common import get_runtime_context as init_runtime_context
from cvif.core.config import AppConfig, load_config
from cvif.version import __version__, __schema_version__

logger = logging.getLogger("cvif.api")


class _PayloadTooLargeError(Exception):
    """Internal sentinel exception for streaming payload overflow."""
    pass


class PayloadSizeLimitMiddleware:
    """ASGI middleware to enforce maximum HTTP request payload size limits.

    Protects against Denial of Service (DoS) and memory exhaustion by rejecting
    requests exceeding configured byte limits at the ASGI boundary (HTTP 413).
    - Checks Content-Length header up-front to reject oversized payloads with 0 memory buffering.
    - Intercepts streaming/chunked request bodies during receive() to terminate streaming as soon as limit is exceeded.
    - Returns standardized CVIF ErrorResponse envelope with correlated X-Request-ID.
    """

    def __init__(self, app: Any, max_bytes: int = 10 * 1024 * 1024) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or self.max_bytes <= 0:
            await self.app(scope, receive, send)
            return

        headers = scope.get("headers", [])

        # 1. Fast-path: Check Content-Length header if present
        content_length: Optional[int] = None
        for name, val in headers:
            if name.lower() == b"content-length":
                try:
                    content_length = int(val.decode("ascii").strip())
                except (ValueError, UnicodeDecodeError):
                    content_length = None
                break

        if content_length is not None and content_length > self.max_bytes:
            await self._send_413(scope, send)
            return

        # 2. Intercept streaming/chunked bodies
        received_bytes = 0
        response_started = False

        async def custom_receive() -> Dict[str, Any]:
            nonlocal received_bytes
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                received_bytes += len(body)
                if received_bytes > self.max_bytes:
                    raise _PayloadTooLargeError()
            return message

        async def custom_send(message: Dict[str, Any]) -> None:
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, custom_receive, custom_send)
        except _PayloadTooLargeError:
            if not response_started:
                await self._send_413(scope, send)

    async def _send_413(self, scope: Dict[str, Any], send: Any) -> None:
        request_id = str(uuid4())
        for name, val in scope.get("headers", []):
            if name.lower() == b"x-request-id":
                try:
                    request_id = val.decode("utf-8").strip()
                except UnicodeDecodeError:
                    pass
                break

        error_payload = {
            "status": "ERROR",
            "error_code": "RESOURCE_EXHAUSTED",
            "message": "Request payload exceeds maximum allowable limit.",
            "details": {},
            "request_id": request_id,
        }
        body_bytes = json.dumps(error_payload).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body_bytes)).encode("ascii")),
                (b"x-request-id", request_id.encode("utf-8")),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body_bytes,
        })


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Inject unique X-Request-ID header into every request/response cycle."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid4()))
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


def create_app(
    config: Optional[AppConfig] = None,
    config_path: Optional[str] = None,
    base_dir: Optional[str] = None,
    frontend_dist: Optional[Union[str, Path]] = None,
    serve_frontend: bool = True,
) -> FastAPI:
    """Construct and configure the CVIF REST API application.

    Parameters
    ----------
    config : AppConfig, optional
        Pre-constructed configuration. If None, loaded from config_path or defaults.
    config_path : str, optional
        Path to YAML configuration file.
    base_dir : str, optional
        Base directory for path resolution.
    frontend_dist : str or Path, optional
        Explicit path to directory containing built frontend static assets.
    serve_frontend : bool, default True
        Whether to mount the React dashboard and static assets.

    Returns
    -------
    FastAPI
        Fully configured CVIF API application instance.
    """
    cfg = config or load_config(config_path)
    if base_dir:
        cfg = cfg.resolve_paths(base_dir)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Initialize RuntimeContext on startup, tear down on shutdown."""
        logger.info("CVIF API starting — initializing runtime context")
        ctx = init_runtime_context(config_path=config_path, base_dir=base_dir)
        # Override config if explicit config was provided
        if config is not None:
            ctx = RuntimeContext(
                config=config,
                db=ctx.db,
                audit=ctx.audit,
                evidence=ctx.evidence,
                keystore=ctx.keystore,
            )
        app.state.ctx = ctx
        logger.info("CVIF API runtime context initialized")
        yield
        logger.info("CVIF API shutting down — releasing runtime context")
        ctx.close()
        logger.info("CVIF API shutdown complete")

    app = FastAPI(
        title="CVIF — Computer Vision Integrity Framework",
        description=(
            "Tamper-evident integrity assurance API for multi-contributor "
            "computer vision pipelines. Provides dataset ingestion, model safety "
            "scanning, inference provenance verification, distribution shift "
            "analysis, and holistic assurance verdicts."
        ),
        version=__version__,
        docs_url="/api/docs" if cfg.api.enable_docs else None,
        redoc_url="/api/redoc" if cfg.api.enable_docs else None,
        openapi_url="/api/openapi.json" if cfg.api.enable_docs else None,
        lifespan=lifespan,
    )

    # ── Middleware ──────────────────────────────────────────────────────
    max_payload_bytes = max(0, cfg.api.max_payload_size_mb * 1024 * 1024)
    app.add_middleware(FrontendSecurityHeadersMiddleware)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(
        PayloadSizeLimitMiddleware,
        max_bytes=max_payload_bytes,
    )

    if cfg.api.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cfg.api.cors_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
            expose_headers=["X-Request-ID"],
        )

    # ── Exception Handlers ─────────────────────────────────────────────
    setup_exception_handlers(app)

    # ── Route Registration ─────────────────────────────────────────────
    api_prefix = "/api/v1"
    app.include_router(health.router, prefix=api_prefix)
    app.include_router(audit.router, prefix=api_prefix)
    app.include_router(datasets.router, prefix=api_prefix)
    app.include_router(models.router, prefix=api_prefix)
    app.include_router(provenance.router, prefix=api_prefix)
    app.include_router(shift.router, prefix=api_prefix)
    app.include_router(assess.router, prefix=api_prefix)
    app.include_router(evidence.router, prefix=api_prefix)

    # ── Frontend Dashboard & Static Serving (Phase 11) ─────────────────
    if serve_frontend:
        dist_dir = get_frontend_dist_dir(
            explicit_path=frontend_dist,
            base_dir=base_dir,
        )
        mount_frontend(app, dist_dir=dist_dir)

    return app


# ── Module-level default application for ``uvicorn cvif.api.main:app`` ─────
app = create_app()
