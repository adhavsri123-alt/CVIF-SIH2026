"""Unit tests for cryptographic primitives and air-gapped KeyStore."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from cvif.core.enums import KeyStatus, KeyType
from cvif.core.exceptions import CVIFCryptographicError
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
from cvif.crypto.keystore import KeyStore


def test_sha256_primitives(temp_dir: Path):
    # String and bytes equivalence
    assert sha256_string("hello world") == sha256_bytes(b"hello world")
    assert sha256_bytes(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Streaming file hashing
    test_file = temp_dir / "stream_test.dat"
    data = b"chunk1" * 1000 + b"chunk2" * 1000
    test_file.write_bytes(data)
    assert sha256_file(test_file, chunk_size=256) == sha256_bytes(data)

    # Canonical JSON hashing
    d1 = {"b": 2, "a": 1}
    d2 = {"a": 1, "b": 2}
    assert sha256_canonical_json(d1) == sha256_canonical_json(d2)


def test_hmac_sha256():
    key = b"super_secret_pipeline_key_12345"
    payload = b"inference_result_data_record_payload"

    mac = compute_hmac_sha256(key, payload)
    assert isinstance(mac, str)
    assert len(mac) == 64

    # Verification success
    assert verify_hmac_sha256(key, payload, mac) is True

    # Tampered payload fails
    assert verify_hmac_sha256(key, b"tampered_payload", mac) is False

    # Corrupted HMAC fails
    corrupted_mac = "0" * 64
    assert verify_hmac_sha256(key, payload, corrupted_mac) is False


def test_ed25519_key_management_and_signing():
    private_key, public_key = generate_ed25519_keypair()
    payload = b"tamper_evident_audit_log_record"

    sig_hex = sign_ed25519(private_key, payload)
    assert isinstance(sig_hex, str)
    assert len(sig_hex) == 128  # 64 bytes = 128 hex chars

    # Valid signature
    assert verify_ed25519(public_key, payload, sig_hex) is True

    # Tampered payload fails
    assert verify_ed25519(public_key, b"tampered_audit_event", sig_hex) is False

    # Corrupted signature fails
    bad_sig = sig_hex[:-4] + "0000"
    assert verify_ed25519(public_key, payload, bad_sig) is False

    # Key export & import round trip
    pub_hex = public_key_to_hex(public_key)
    priv_hex = private_key_to_hex(private_key)
    reloaded_pub = public_key_from_hex(pub_hex)
    reloaded_priv = private_key_from_hex(priv_hex)

    sig2 = sign_ed25519(reloaded_priv, payload)
    assert verify_ed25519(reloaded_pub, payload, sig2) is True


def test_keystore_lifecycle(temp_dir: Path):
    store_file = temp_dir / "truststore.json"
    keystore = KeyStore(persistence_path=store_file)

    priv_key, pub_key = generate_ed25519_keypair()
    key_id = "contributor_node_42"

    # Register active public key
    record = keystore.register_public_key(
        key_id=key_id,
        owner_entity="Field Recon Unit 9",
        public_key=pub_key,
        valid_until=datetime.now(timezone.utc) + timedelta(days=30),
    )
    assert record.status == KeyStatus.ACTIVE

    valid, msg = keystore.check_key_validity(key_id)
    assert valid is True

    # Register HMAC secret
    keystore.register_hmac_secret(
        key_id="hmac_edge_1",
        owner_entity="Edge Device 1",
        secret=b"device_shared_secret_999",
    )
    assert keystore.get_hmac_secret("hmac_edge_1") == b"device_shared_secret_999"

    # Suspend key
    keystore.suspend_key(key_id)
    valid, msg = keystore.check_key_validity(key_id)
    assert valid is False
    assert "SUSPENDED" in msg

    # Revoke key
    keystore.revoke_key(key_id)
    valid, msg = keystore.check_key_validity(key_id)
    assert valid is False
    assert "REVOKED" in msg

    # Persistence verification: reload from disk
    new_store = KeyStore(persistence_path=store_file)
    assert new_store.get_key_record(key_id).status == KeyStatus.REVOKED
    assert new_store.get_hmac_secret("hmac_edge_1") == b"device_shared_secret_999"


def test_keystore_expired_key(temp_dir: Path):
    keystore = KeyStore()
    _, pub_key = generate_ed25519_keypair()

    # Expired 1 hour ago
    past_time = datetime.now(timezone.utc) - timedelta(hours=1)
    keystore.register_public_key(
        key_id="expired_key",
        owner_entity="Old Sensor",
        public_key=pub_key,
        valid_until=past_time,
    )

    valid, msg = keystore.check_key_validity("expired_key")
    assert valid is False
    assert "expired" in msg.lower()
