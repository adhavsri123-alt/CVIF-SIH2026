"""Consistent exception hierarchy for the CVIF architecture."""

from typing import Any, Dict, Optional


class CVIFError(Exception):
    """Base exception for all errors originating within the CVIF framework."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


class SchemaValidationError(CVIFError):
    """Raised when data contracts or payloads violate architectural schema constraints."""


class UnsupportedFormatError(CVIFError):
    """Raised when an asset format is unrecognized or unsupported."""


class CorruptedArtifactError(CVIFError):
    """Raised when an asset, manifest, or stored file is corrupted or fails integrity check."""


class InvalidModelError(CVIFError):
    """Raised when a model file fails validation or cannot be safely loaded."""


class CryptographicError(CVIFError):
    """Raised on failure of cryptographic primitives (hashing, signing, HMAC, chain)."""


class TamperDetectedError(CryptographicError):
    """Raised specifically when post-hoc alteration, replay, or audit chain break is detected."""


class StorageError(CVIFError):
    """Raised when a storage, database, or file write/read operation fails."""


class PathTraversalError(StorageError):
    """Raised when a path traversal attempt is detected during file or archive operations."""


class ConfigurationError(CVIFError):
    """Raised when required configuration settings are missing or invalid."""


class AirGapViolationError(CVIFError):
    """Raised when an operation attempts external network connectivity in air-gap mode."""


class AccessDeniedError(CVIFError):
    """Raised when a white-box inspection method is invoked on a black-box model."""


class EvidenceImmutableError(StorageError):
    """Raised when an attempt is made to overwrite or modify an existing evidence record."""


class KeyNotFoundError(CryptographicError):
    """Raised when a requested signing_key_id is absent from the local trust store."""


class ResourceExhaustionError(CVIFError):
    """Raised when model size, memory, iteration budget, or inference count exceeds limits."""


# Aliases for consistent naming
CVIFResourceError = ResourceExhaustionError
CVIFValidationError = SchemaValidationError
CVIFFormatError = UnsupportedFormatError
CVIFCorruptedArtifactError = CorruptedArtifactError
CVIFInvalidModelError = InvalidModelError
CVIFCryptographicError = CryptographicError
CVIFAuditChainError = TamperDetectedError
CVIFStorageError = StorageError
CVIFPathTraversalError = PathTraversalError
CVIFConfigurationError = ConfigurationError
CVIFProvenanceError = CryptographicError
CVIFImmutableError = EvidenceImmutableError
