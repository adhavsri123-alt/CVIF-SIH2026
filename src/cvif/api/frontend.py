"""Static frontend mounting and SPA routing for CVIF REST API (Phase 11).

Provides:
- Production React dashboard serving from frontend/dist
- Content Security Policy (CSP) enforcement with strict air-gap compliance
- Defensive browser headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
- Secure SPA fallback for client-side routing (/dashboard, /dataset, /model, etc.)
- Strict boundary protection: API routes under /api/* are NEVER swallowed by SPA
- Path traversal defense preventing leakage of source code, SQLite databases, and secrets
- Clean failure mode when frontend/dist is missing or unbuilt
"""

import logging
from pathlib import Path
from typing import Optional, Set, Union

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

logger = logging.getLogger("cvif.api.frontend")

# ── Content Security Policy & Security Headers (Phase 11 / Threat T-11-2) ───
# Prohibits external scripts, styles, fonts, objects, frames, and connections.
# Local CVIF REST API is strictly permitted under 'self'.
# 'unsafe-inline' is permitted for styles only (required by React JSX inline style attributes).
CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

FRONTEND_SECURITY_HEADERS = {
    "Content-Security-Policy": CSP_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

# Blocked extensions to prevent inadvertent source code, database, or secret exposure
BLOCKED_EXTENSIONS: Set[str] = {
    ".py",
    ".pyc",
    ".pyo",
    ".pyd",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".env",
    ".key",
    ".pem",
    ".cert",
    ".crt",
    ".jsonl",
    ".log",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".map",
}

BLOCKED_PREFIXES = ("src/", "data/", "tests/", "config/", ".git/", "test/")

# Authoritative frontend SPA top-level routes
SPA_ROUTES = (
    "dashboard",
    "overview",
    "dataset",
    "model",
    "provenance",
    "shift",
    "assurance",
    "evidence",
    "audit",
)


class FrontendSecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforce Content Security Policy and defensive browser headers for all frontend responses."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        for header, value in FRONTEND_SECURITY_HEADERS.items():
            response.headers[header] = value
        return response


def get_frontend_dist_dir(
    explicit_path: Optional[Union[str, Path]] = None,
    base_dir: Optional[Union[str, Path]] = None,
) -> Path:
    """Resolve the directory containing built static frontend assets.

    Searches in order:
    1. Explicitly supplied path
    2. base_dir / frontend / dist
    3. Repository root / frontend / dist (relative to this package)
    4. Current working directory / frontend / dist
    """
    if explicit_path:
        return Path(explicit_path).resolve()

    if base_dir:
        candidate = (Path(base_dir) / "frontend" / "dist").resolve()
        if candidate.is_dir():
            return candidate

    # Relative to package: src/cvif/api/frontend.py -> repo_root / frontend / dist
    repo_root = Path(__file__).resolve().parents[3]
    candidate = (repo_root / "frontend" / "dist").resolve()
    if candidate.is_dir():
        return candidate

    cwd_candidate = (Path.cwd() / "frontend" / "dist").resolve()
    if cwd_candidate.is_dir():
        return cwd_candidate

    return candidate


def mount_frontend(
    app: FastAPI,
    dist_dir: Optional[Union[str, Path]] = None,
) -> None:
    """Mount compiled React dashboard and static assets into FastAPI.

    Registers:
    - /assets mount for compiled JavaScript and CSS bundles
    - Root ('/') and designated SPA routes (/dashboard, /dataset, /model, etc.) fallback to index.html
    - Strict boundary enforcement: /api/* routes are never swallowed by the SPA
    - Path traversal checks to confine static file access strictly to dist_dir
    - Clean 404 behavior if frontend/dist is missing or unbuilt
    """
    resolved_dist = (
        Path(dist_dir).resolve() if dist_dir else get_frontend_dist_dir()
    )
    assets_dir = resolved_dist / "assets"
    index_file = resolved_dist / "index.html"

    # Mount static assets subdirectory if present
    if assets_dir.is_dir():
        app.mount(
            "/assets",
            StaticFiles(directory=str(assets_dir)),
            name="frontend-assets",
        )

    def _serve_spa(clean_path: str = "") -> FileResponse:
        # Strict boundary: API routes and test routes must never be handled by SPA fallback
        if (
            clean_path == "api"
            or clean_path.startswith("api/")
            or clean_path.startswith("test/")
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"API endpoint '/{clean_path}' not found",
            )

        # Fail clearly and safely if frontend build is missing
        if not (resolved_dist.is_dir() and index_file.is_file()):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    "CVIF Dashboard frontend production build not found at frontend/dist. "
                    "Run 'npm run build' in the frontend directory before accessing the UI."
                ),
            )

        path_obj = Path(clean_path)

        # Block dotfiles, hidden files, sensitive extensions, and source directory prefixes
        if any(part.startswith(".") for part in path_obj.parts):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Not Found"
            )
        if path_obj.suffix.lower() in BLOCKED_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Not Found"
            )
        if any(clean_path.startswith(prefix) for prefix in BLOCKED_PREFIXES):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Not Found"
            )

        # Path traversal prevention: strictly confine access to resolved_dist
        if clean_path:
            target = (resolved_dist / clean_path).resolve()
            try:
                is_safe = target.is_relative_to(resolved_dist)
            except (ValueError, AttributeError):
                is_safe = False

            if not is_safe:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Path traversal detected",
                )

            # Serve existing static file from dist root (e.g. favicon.ico)
            if target.is_file():
                return FileResponse(target)

            # If a file with an extension was requested but does not exist, return 404
            if path_obj.suffix:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Static asset '/{clean_path}' not found",
                )

        # SPA route: return index.html
        return FileResponse(index_file, media_type="text/html")

    @app.get("/", include_in_schema=False)
    async def frontend_root() -> FileResponse:
        return _serve_spa("")

    # Register handlers for each SPA route
    for route in SPA_ROUTES:
        endpoint_name = f"frontend_spa_{route}"

        def _make_spa_handler():
            async def _handler(request: Request) -> FileResponse:
                clean = request.url.path.lstrip("/")
                return _serve_spa(clean)

            return _handler

        app.add_api_route(
            f"/{route}",
            _make_spa_handler(),
            methods=["GET"],
            include_in_schema=False,
            name=endpoint_name,
        )
        app.add_api_route(
            f"/{route}/{{subpath:path}}",
            _make_spa_handler(),
            methods=["GET"],
            include_in_schema=False,
            name=f"{endpoint_name}_sub",
        )

    # Specific static files in dist root
    @app.get("/favicon.ico", include_in_schema=False)
    async def frontend_favicon() -> FileResponse:
        return _serve_spa("favicon.ico")
