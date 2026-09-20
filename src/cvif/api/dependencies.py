"""Dependency injection and security validation helpers for CVIF REST API (Phase 10)."""

from pathlib import Path
from typing import Optional, Union

from fastapi import Depends, Header, HTTPException, Request, status

from cvif.cli.commands.common import RuntimeContext
from cvif.core.exceptions import PathTraversalError


def get_runtime_context(request: Request) -> RuntimeContext:
    """Retrieve application-scoped RuntimeContext containing initialized services."""
    ctx = getattr(request.app.state, "ctx", None)
    if ctx is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="RuntimeContext is not initialized on the application state.",
        )
    return ctx


def resolve_api_path(
    path_str: Union[str, Path],
    base_dir: Optional[Path] = None,
    must_exist: bool = False,
) -> Path:
    """Sanitize and resolve user-supplied filesystem path, strictly defending against path traversal.
    
    Prohibits:
    - Null bytes (\x00)
    - Directory traversal escapes (..)
    - Absolute path escapes when a base directory is mandated
    - Windows UNC network shares (\\\\server\\share)
    """
    raw_str = str(path_str).strip()
    if not raw_str:
        raise PathTraversalError("Path cannot be empty")

    if "\x00" in raw_str:
        raise PathTraversalError("Path traversal detected: null byte in path")

    if raw_str.startswith(("\\\\", "//")):
        raise PathTraversalError("Path traversal detected: UNC network shares are prohibited")

    # Normalize separators
    normalized = raw_str.replace("\\", "/")
    parts = normalized.split("/")
    if ".." in parts:
        raise PathTraversalError("Path traversal detected: directory traversal '..' is prohibited")

    candidate = Path(raw_str)
    if not candidate.is_absolute() and base_dir is not None:
        resolved = (base_dir / candidate).resolve()
    else:
        resolved = candidate.resolve()

    if base_dir is not None:
        resolved_base = base_dir.resolve()
        try:
            resolved.relative_to(resolved_base)
        except ValueError:
            # Check if resolved equals base or falls inside
            if not str(resolved).startswith(str(resolved_base)):
                raise PathTraversalError(
                    f"Path traversal detected: path '{raw_str}' escapes allowed root '{base_dir}'"
                )

    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"Target path does not exist: {resolved}")

    return resolved


def verify_api_key(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    ctx: RuntimeContext = Depends(get_runtime_context),
) -> None:
    """Optional defense-in-depth API key verification when enabled in configuration."""
    if not ctx.config.api.api_key_enabled:
        return

    configured_keys = ctx.config.api.api_keys or []
    if not x_api_key or x_api_key not in configured_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )
