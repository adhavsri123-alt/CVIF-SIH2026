"""HMAC-SHA256 operations for cryptographically binding inference records and messages."""

import hmac
import hashlib
from typing import Union

from cvif.core.exceptions import CVIFCryptographicError


def compute_hmac_sha256(key: Union[bytes, str], payload: bytes) -> str:
    """Compute HMAC-SHA256 hex digest over payload bytes."""
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not isinstance(key, (bytes, bytearray)):
        raise CVIFCryptographicError("HMAC key must be bytes or str")
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise CVIFCryptographicError("HMAC payload must be bytes-like")

    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_hmac_sha256(key: Union[bytes, str], payload: bytes, expected_hex: str) -> bool:
    """Verify HMAC-SHA256 digest in constant time to prevent timing attacks."""
    if not expected_hex or not isinstance(expected_hex, str):
        return False
    computed = compute_hmac_sha256(key, payload)
    return hmac.compare_digest(computed.lower(), expected_hex.lower())
