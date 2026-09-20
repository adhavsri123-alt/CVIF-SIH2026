"""Centralized exception handling for CVIF REST API (Phase 10).

Prevents sensitive technical information and stack trace leakage (Threat CT-12 / T-10-5)
while providing deterministic machine-readable JSON error envelopes with unique request IDs.
"""

import logging
from typing import Any, Dict, Optional
from uuid import uuid4

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from cvif.api.schemas import ErrorResponse
from cvif.core.exceptions import (
    AccessDeniedError,
    AirGapViolationError,
    ConfigurationError,
    CorruptedArtifactError,
    CVIFError,
    EvidenceImmutableError,
    InvalidModelError,
    KeyNotFoundError,
    PathTraversalError,
    ResourceExhaustionError,
    SchemaValidationError,
    StorageError,
    TamperDetectedError,
    UnsupportedFormatError,
)

logger = logging.getLogger("cvif.api.error_handler")

# Backward-compatible reference for Starlette RFC 9110 status code rename
HTTP_422_UNPROCESSABLE = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)


def _get_request_id(request: Request) -> str:
    """Retrieve existing request correlation ID or generate fresh UUID."""
    return getattr(request.state, "request_id", str(uuid4()))


def _build_error_response(
    status_code: int,
    error_code: str,
    message: str,
    request: Request,
    details: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    """Format standard error envelope JSONResponse."""
    req_id = _get_request_id(request)
    payload = ErrorResponse(
        status="ERROR",
        error_code=error_code,
        message=message,
        details=details or {},
        request_id=req_id,
    ).model_dump(mode="json")
    return JSONResponse(
        status_code=status_code,
        content=payload,
        headers={"X-Request-ID": req_id},
    )


def setup_exception_handlers(app: FastAPI) -> None:
    """Register authoritative domain exception handlers on the FastAPI application."""

    @app.exception_handler(PathTraversalError)
    async def path_traversal_handler(request: Request, exc: PathTraversalError) -> JSONResponse:
        logger.warning(f"Path traversal detected: {exc.message}")
        return _build_error_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code="PATH_TRAVERSAL_DETECTED",
            message=str(exc.message),
            request=request,
            details=exc.details,
        )

    @app.exception_handler(TamperDetectedError)
    async def tamper_handler(request: Request, exc: TamperDetectedError) -> JSONResponse:
        logger.error(f"Cryptographic tampering detected: {exc.message}")
        return _build_error_response(
            status_code=status.HTTP_409_CONFLICT,
            error_code="TAMPER_DETECTED",
            message=str(exc.message),
            request=request,
            details=exc.details,
        )

    @app.exception_handler(EvidenceImmutableError)
    async def immutable_handler(request: Request, exc: EvidenceImmutableError) -> JSONResponse:
        logger.warning(f"Evidence immutability violation: {exc.message}")
        return _build_error_response(
            status_code=status.HTTP_409_CONFLICT,
            error_code="EVIDENCE_IMMUTABLE",
            message=str(exc.message),
            request=request,
            details=exc.details,
        )

    @app.exception_handler(KeyNotFoundError)
    async def key_not_found_handler(request: Request, exc: KeyNotFoundError) -> JSONResponse:
        return _build_error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="KEY_NOT_FOUND",
            message=str(exc.message),
            request=request,
            details=exc.details,
        )

    @app.exception_handler(InvalidModelError)
    async def invalid_model_handler(request: Request, exc: InvalidModelError) -> JSONResponse:
        logger.warning(f"Model safety validation failure: {exc.message}")
        return _build_error_response(
            status_code=HTTP_422_UNPROCESSABLE,
            error_code="INVALID_MODEL",
            message=str(exc.message),
            request=request,
            details=exc.details,
        )

    @app.exception_handler(UnsupportedFormatError)
    async def unsupported_format_handler(request: Request, exc: UnsupportedFormatError) -> JSONResponse:
        return _build_error_response(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            error_code="UNSUPPORTED_FORMAT",
            message=str(exc.message),
            request=request,
            details=exc.details,
        )

    @app.exception_handler(ResourceExhaustionError)
    async def resource_exhaustion_handler(request: Request, exc: ResourceExhaustionError) -> JSONResponse:
        logger.warning(f"Resource exhaustion boundary hit: {exc.message}")
        return _build_error_response(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            error_code="RESOURCE_EXHAUSTED",
            message=str(exc.message),
            request=request,
            details=exc.details,
        )

    @app.exception_handler(AirGapViolationError)
    async def air_gap_handler(request: Request, exc: AirGapViolationError) -> JSONResponse:
        logger.error(f"Air-gap egress violation blocked: {exc.message}")
        return _build_error_response(
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="AIR_GAP_VIOLATION",
            message=str(exc.message),
            request=request,
            details=exc.details,
        )

    @app.exception_handler(AccessDeniedError)
    async def access_denied_handler(request: Request, exc: AccessDeniedError) -> JSONResponse:
        return _build_error_response(
            status_code=status.HTTP_403_FORBIDDEN,
            error_code="ACCESS_DENIED",
            message=str(exc.message),
            request=request,
            details=exc.details,
        )

    @app.exception_handler(SchemaValidationError)
    async def schema_val_handler(request: Request, exc: SchemaValidationError) -> JSONResponse:
        return _build_error_response(
            status_code=HTTP_422_UNPROCESSABLE,
            error_code="VALIDATION_ERROR",
            message=str(exc.message),
            request=request,
            details=exc.details,
        )

    @app.exception_handler(ConfigurationError)
    async def config_handler(request: Request, exc: ConfigurationError) -> JSONResponse:
        logger.error(f"Configuration error: {exc.message}")
        return _build_error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="CONFIG_ERROR",
            message=str(exc.message),
            request=request,
            details=exc.details,
        )

    @app.exception_handler(StorageError)
    async def storage_handler(request: Request, exc: StorageError) -> JSONResponse:
        logger.error(f"Storage error: {exc.message}")
        return _build_error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="STORAGE_ERROR",
            message=str(exc.message),
            request=request,
            details=exc.details,
        )

    @app.exception_handler(FileNotFoundError)
    async def file_not_found_handler(request: Request, exc: FileNotFoundError) -> JSONResponse:
        return _build_error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="RESOURCE_NOT_FOUND",
            message=f"Requested resource or file was not found: {exc}",
            request=request,
        )

    @app.exception_handler(KeyError)
    async def key_error_handler(request: Request, exc: KeyError) -> JSONResponse:
        return _build_error_response(
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="RESOURCE_NOT_FOUND",
            message=f"Resource key not found: {exc}",
            request=request,
        )

    @app.exception_handler(CVIFError)
    async def general_cvif_handler(request: Request, exc: CVIFError) -> JSONResponse:
        logger.warning(f"Domain error ({exc.__class__.__name__}): {exc.message}")
        return _build_error_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code=exc.__class__.__name__.upper(),
            message=str(exc.message),
            request=request,
            details=exc.details,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = exc.errors()
        return _build_error_response(
            status_code=HTTP_422_UNPROCESSABLE,
            error_code="REQUEST_VALIDATION_ERROR",
            message="Request body or parameter validation failed",
            request=request,
            details={"validation_errors": errors},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        req_id = _get_request_id(request)
        logger.exception(f"Unhandled server exception [request_id={req_id}]: {exc}")
        return _build_error_response(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_code="INTERNAL_SERVER_ERROR",
            message="An internal server error occurred while processing the request.",
            request=request,
        )
