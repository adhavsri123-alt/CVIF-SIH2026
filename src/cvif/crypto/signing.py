"""Ed25519 digital signature operations for CVIF provenance and audit assurance."""

from typing import Tuple, Union
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from cvif.core.exceptions import CVIFCryptographicError


def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a fresh Ed25519 private/public key pair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def private_key_to_raw_bytes(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Export private key to raw 32 bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_raw_bytes(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Export public key to raw 32 bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_key_to_hex(private_key: ed25519.Ed25519PrivateKey) -> str:
    """Convert Ed25519 private key to hex string."""
    return private_key_to_raw_bytes(private_key).hex()


def public_key_to_hex(public_key: ed25519.Ed25519PublicKey) -> str:
    """Convert Ed25519 public key to hex string."""
    return public_key_to_raw_bytes(public_key).hex()


def private_key_from_hex(hex_str: str) -> ed25519.Ed25519PrivateKey:
    """Construct Ed25519 private key from 64-char hex string (32 raw bytes)."""
    try:
        raw_bytes = bytes.fromhex(hex_str.strip())
        if len(raw_bytes) != 32:
            raise CVIFCryptographicError(f"Invalid private key length: expected 32 bytes, got {len(raw_bytes)}")
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)
    except Exception as e:
        if isinstance(e, CVIFCryptographicError):
            raise
        raise CVIFCryptographicError(f"Failed to parse Ed25519 private key from hex: {e}") from e


def public_key_from_hex(hex_str: str) -> ed25519.Ed25519PublicKey:
    """Construct Ed25519 public key from 64-char hex string (32 raw bytes)."""
    try:
        raw_bytes = bytes.fromhex(hex_str.strip())
        if len(raw_bytes) != 32:
            raise CVIFCryptographicError(f"Invalid public key length: expected 32 bytes, got {len(raw_bytes)}")
        return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)
    except Exception as e:
        if isinstance(e, CVIFCryptographicError):
            raise
        raise CVIFCryptographicError(f"Failed to parse Ed25519 public key from hex: {e}") from e


def sign_ed25519(private_key: ed25519.Ed25519PrivateKey, payload: bytes) -> str:
    """Sign payload bytes using Ed25519 private key and return hex signature."""
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise CVIFCryptographicError("Payload to sign must be bytes-like")
    try:
        sig_bytes = private_key.sign(bytes(payload))
        return sig_bytes.hex()
    except Exception as e:
        raise CVIFCryptographicError(f"Ed25519 signing failed: {e}") from e


def verify_ed25519(
    public_key: Union[ed25519.Ed25519PublicKey, str],
    payload: bytes,
    signature_hex: str,
) -> bool:
    """Verify Ed25519 signature over payload bytes. Returns True if valid, False otherwise."""
    if isinstance(public_key, str):
        try:
            public_key = public_key_from_hex(public_key)
        except Exception:
            return False

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        return False

    if not signature_hex or not isinstance(signature_hex, str):
        return False

    try:
        sig_bytes = bytes.fromhex(signature_hex.strip())
        public_key.verify(sig_bytes, bytes(payload))
        return True
    except (InvalidSignature, ValueError):
        return False
    except Exception:
        return False
