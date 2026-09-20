"""Cryptographic services package for CVIF."""

from cvif.crypto.hashing import (
    sha256_bytes,
    sha256_string,
    sha256_file,
    sha256_canonical_json,
)
from cvif.crypto.hmac import compute_hmac_sha256, verify_hmac_sha256
from cvif.crypto.signing import (
    generate_ed25519_keypair,
    private_key_to_hex,
    public_key_to_hex,
    private_key_from_hex,
    public_key_from_hex,
    sign_ed25519,
    verify_ed25519,
)
from cvif.crypto.chain import (
    GENESIS_PREVIOUS_HASH,
    ArchiveVerificationResult,
    ChainVerificationResult,
    verify_event_hash,
    verify_audit_chain,
    verify_archive_manifest,
)
from cvif.crypto.keystore import KeyStore

__all__ = [
    # Hashing
    "sha256_bytes",
    "sha256_string",
    "sha256_file",
    "sha256_canonical_json",
    # HMAC
    "compute_hmac_sha256",
    "verify_hmac_sha256",
    # Ed25519
    "generate_ed25519_keypair",
    "private_key_to_hex",
    "public_key_to_hex",
    "private_key_from_hex",
    "public_key_from_hex",
    "sign_ed25519",
    "verify_ed25519",
    # Hash Chain
    "GENESIS_PREVIOUS_HASH",
    "ArchiveVerificationResult",
    "ChainVerificationResult",
    "verify_event_hash",
    "verify_audit_chain",
    "verify_archive_manifest",
    # KeyStore
    "KeyStore",
]
