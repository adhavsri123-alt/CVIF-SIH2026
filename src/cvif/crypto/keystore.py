"""Local cryptographic trust store for air-gapped key management."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import json
import threading

from cryptography.hazmat.primitives.asymmetric import ed25519

from cvif.core.enums import KeyStatus, KeyType
from cvif.core.exceptions import CVIFCryptographicError
from cvif.core.schemas import KeyRecord, utc_now
from cvif.crypto.signing import public_key_from_hex, public_key_to_hex


class KeyStore:
    """Thread-safe, air-gapped local trust store for Ed25519 public keys and HMAC secrets."""

    def __init__(self, persistence_path: Optional[Union[str, Path]] = None):
        self._lock = threading.RLock()
        self._keys: Dict[str, KeyRecord] = {}
        self._hmac_secrets: Dict[str, bytes] = {}
        self._persistence_path = Path(persistence_path) if persistence_path else None

        if self._persistence_path and self._persistence_path.is_file():
            self.load()

    def register_public_key(
        self,
        key_id: str,
        owner_entity: str,
        public_key: Union[ed25519.Ed25519PublicKey, str],
        valid_until: Optional[datetime] = None,
    ) -> KeyRecord:
        """Register an Ed25519 public key in the trust store."""
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            hex_str = public_key_to_hex(public_key)
        elif isinstance(public_key, str):
            # Validate hex
            public_key_from_hex(public_key)
            hex_str = public_key.strip()
        else:
            raise CVIFCryptographicError("public_key must be Ed25519PublicKey or hex string")

        with self._lock:
            record = KeyRecord(
                key_id=key_id,
                key_type=KeyType.ED25519_PUBLIC,
                owner_entity=owner_entity,
                public_key_hex=hex_str,
                status=KeyStatus.ACTIVE,
                valid_from=utc_now(),
                valid_until=valid_until,
            )
            self._keys[key_id] = record
            self._save()
            return record

    def register_hmac_secret(
        self,
        key_id: str,
        owner_entity: str,
        secret: Union[bytes, str],
        valid_until: Optional[datetime] = None,
    ) -> KeyRecord:
        """Register an HMAC secret in the trust store."""
        if isinstance(secret, str):
            secret_bytes = secret.encode("utf-8")
        elif isinstance(secret, (bytes, bytearray)):
            secret_bytes = bytes(secret)
        else:
            raise CVIFCryptographicError("HMAC secret must be bytes or string")

        with self._lock:
            record = KeyRecord(
                key_id=key_id,
                key_type=KeyType.HMAC_SECRET,
                owner_entity=owner_entity,
                public_key_hex=None,
                status=KeyStatus.ACTIVE,
                valid_from=utc_now(),
                valid_until=valid_until,
            )
            self._keys[key_id] = record
            self._hmac_secrets[key_id] = secret_bytes
            self._save()
            return record

    def get_key_record(self, key_id: str) -> Optional[KeyRecord]:
        """Retrieve key metadata record."""
        with self._lock:
            return self._keys.get(key_id)

    def get_public_key(self, key_id: str) -> Optional[ed25519.Ed25519PublicKey]:
        """Retrieve and parse Ed25519 public key if active and valid."""
        with self._lock:
            record = self._keys.get(key_id)
            if not record or not record.public_key_hex:
                return None
            return public_key_from_hex(record.public_key_hex)

    def get_hmac_secret(self, key_id: str) -> Optional[bytes]:
        """Retrieve raw HMAC secret bytes."""
        with self._lock:
            return self._hmac_secrets.get(key_id)

    def check_key_validity(self, key_id: str) -> Tuple[bool, str]:
        """Check whether key is registered, ACTIVE, and not expired."""
        with self._lock:
            record = self._keys.get(key_id)
            if not record:
                return False, f"Key '{key_id}' not found in trust store"

            if record.status != KeyStatus.ACTIVE:
                return False, f"Key '{key_id}' is {record.status.value}"

            now = utc_now()
            if record.valid_until and now > record.valid_until:
                return False, f"Key '{key_id}' has expired (expired at {record.valid_until.isoformat()})"

            if record.valid_from and now < record.valid_from:
                return False, f"Key '{key_id}' is not yet valid (valid from {record.valid_from.isoformat()})"

            return True, "Key is valid and active"

    def set_key_status(self, key_id: str, status: KeyStatus) -> bool:
        """Update lifecycle status of a key."""
        with self._lock:
            record = self._keys.get(key_id)
            if not record:
                return False
            record.status = status
            self._save()
            return True

    def revoke_key(self, key_id: str) -> bool:
        """Revoke a key."""
        return self.set_key_status(key_id, KeyStatus.REVOKED)

    def suspend_key(self, key_id: str) -> bool:
        """Suspend a key temporarily."""
        return self.set_key_status(key_id, KeyStatus.SUSPENDED)

    def list_keys(self, status: Optional[KeyStatus] = None) -> List[KeyRecord]:
        """List stored key records, optionally filtered by status."""
        with self._lock:
            if status is None:
                return list(self._keys.values())
            return [k for k in self._keys.values() if k.status == status]

    def _save(self) -> None:
        """Persist public keys to disk if persistence path is configured."""
        if not self._persistence_path:
            return
        data = {
            "keys": [k.model_dump(mode="json") for k in self._keys.values()],
            "hmac_secrets": {k: v.hex() for k, v in self._hmac_secrets.items()},
        }
        self._persistence_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self._persistence_path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        temp_path.replace(self._persistence_path)

    def load(self) -> None:
        """Load stored keys from disk."""
        if not self._persistence_path or not self._persistence_path.is_file():
            return
        with self._lock:
            try:
                with self._persistence_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                self._keys = {k["key_id"]: KeyRecord(**k) for k in data.get("keys", [])}
                self._hmac_secrets = {
                    k: bytes.fromhex(v) for k, v in data.get("hmac_secrets", {}).items()
                }
            except Exception as e:
                raise CVIFCryptographicError(f"Failed to load keystore from {self._persistence_path}: {e}") from e
