"""Cryptographic hashing services for CVIF."""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Union

from cvif.core.exceptions import CVIFCryptographicError, CVIFStorageError


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hex digest of raw byte sequence."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise CVIFCryptographicError(f"Expected bytes-like object, got {type(data).__name__}")
    return hashlib.sha256(data).hexdigest()


def sha256_string(text: str) -> str:
    """Compute SHA-256 hex digest of UTF-8 encoded string."""
    if not isinstance(text, str):
        raise CVIFCryptographicError(f"Expected string, got {type(text).__name__}")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(file_path: Union[str, Path], chunk_size: int = 65536) -> str:
    """Compute SHA-256 hex digest of a file using streaming reads to prevent memory exhaustion."""
    path = Path(file_path)
    if not path.is_file():
        raise CVIFStorageError(f"File not found or not a regular file: {path}")

    hasher = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
    except OSError as e:
        raise CVIFStorageError(f"Failed to read file for hashing {path}: {e}") from e

    return hasher.hexdigest()


def sha256_canonical_json(data: Dict[str, Any]) -> str:
    """Compute SHA-256 hex digest over canonical JSON representation."""
    try:
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()
    except (TypeError, ValueError) as e:
        raise CVIFCryptographicError(f"Failed to produce canonical JSON for hashing: {e}") from e
