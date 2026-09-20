"""Centralized exception boundary and exit-code mapping for CVIF CLI.

Converts core domain exceptions into deterministic exit codes and formatted stderr diagnostics.
Suppresses raw stack traces by default to prevent technical information leakage (Threat CT-12).
"""

from functools import wraps
import sys
import traceback
from typing import Any, Callable

import typer

from cvif.cli.exit_codes import (
    EXIT_CLI_ERROR,
    EXIT_CONFIG_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_MODEL_INTEGRITY_FINDING,
    EXIT_NOT_FOUND,
    EXIT_TAMPER_DETECTED,
    EXIT_UNSUPPORTED,
    EXIT_VALIDATION_ERROR,
)
from cvif.cli.output import emit_error
from cvif.core.exceptions import (
    ConfigurationError,
    CorruptedArtifactError,
    CVIFError,
    EvidenceImmutableError,
    InvalidModelError,
    KeyNotFoundError,
    PathTraversalError,
    SchemaValidationError,
    StorageError,
    TamperDetectedError,
    UnsupportedFormatError,
)


def map_exception_to_exit_code(exc: Exception) -> int:
    """Map a caught exception to its audited deterministic exit code."""
    if isinstance(exc, ConfigurationError):
        return EXIT_CONFIG_ERROR
    if isinstance(exc, SchemaValidationError):
        return EXIT_VALIDATION_ERROR
    if isinstance(exc, UnsupportedFormatError):
        return EXIT_UNSUPPORTED
    if isinstance(exc, InvalidModelError):
        return EXIT_MODEL_INTEGRITY_FINDING
    if isinstance(exc, (TamperDetectedError, EvidenceImmutableError, CorruptedArtifactError)):
        return EXIT_TAMPER_DETECTED
    if isinstance(exc, KeyNotFoundError):
        return EXIT_NOT_FOUND
    if isinstance(exc, (PathTraversalError, StorageError)):
        return EXIT_CLI_ERROR
    if isinstance(exc, FileNotFoundError):
        return EXIT_CLI_ERROR
    if isinstance(exc, KeyError):
        return EXIT_NOT_FOUND
    if isinstance(exc, CVIFError):
        return EXIT_CLI_ERROR
    return EXIT_INTERNAL_ERROR


def cli_error_boundary(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator establishing the centralized CLI exception boundary."""
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        json_mode: bool = kwargs.get("json_mode", False)
        debug_mode: bool = kwargs.get("debug", False)
        try:
            return func(*args, **kwargs)
        except typer.Exit:
            # Propagate intentional Typer/CLI exits untouched
            raise
        except SystemExit:
            raise
        except Exception as exc:
            exit_code = map_exception_to_exit_code(exc)
            if debug_mode:
                traceback.print_exc(file=sys.stderr)
            emit_error(
                message=str(exc),
                json_mode=json_mode,
                exit_code=exit_code,
                details=getattr(exc, "details", None),
            )
            raise typer.Exit(code=exit_code) from exc

    return wrapper
