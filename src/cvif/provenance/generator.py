"""Mode 1: Inference Provenance Record Generator.

Generates cryptographically bound InferenceRecords for local or deployed models
using either Ed25519 asymmetric signatures or HMAC-SHA256 symmetric MACs.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Union
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric import ed25519

from cvif.core.enums import RecordOrigin
from cvif.core.exceptions import CVIFCryptographicError
from cvif.core.schemas import InferenceRecord, PredictionResult, utc_now
from cvif.crypto.hashing import sha256_bytes, sha256_canonical_json, sha256_file
from cvif.crypto.hmac import compute_hmac_sha256
from cvif.crypto.signing import private_key_from_hex, sign_ed25519


class InferenceProvenanceGenerator:
    """Produces authenticated InferenceRecords with deterministic canonicalization and replay metadata."""

    def __init__(
        self,
        signing_key_id: str,
        private_key: Optional[Union[ed25519.Ed25519PrivateKey, str]] = None,
        hmac_secret: Optional[Union[bytes, str]] = None,
        producer_id: Optional[str] = None,
        origin: RecordOrigin = RecordOrigin.EXTERNAL,
        default_session_id: Optional[Union[str, UUID]] = None,
    ):
        if not signing_key_id:
            raise CVIFCryptographicError("signing_key_id is required for provenance generator")
        if private_key is None and hmac_secret is None:
            raise CVIFCryptographicError(
                "At least one cryptographic signing credential (private_key or hmac_secret) must be provided"
            )

        self.signing_key_id = signing_key_id
        self.producer_id = producer_id
        self.origin = origin
        self.default_session_id = (
            UUID(str(default_session_id)) if default_session_id else uuid4()
        )

        if isinstance(private_key, str):
            self._private_key: Optional[ed25519.Ed25519PrivateKey] = private_key_from_hex(private_key)
        else:
            self._private_key = private_key

        if isinstance(hmac_secret, str):
            self._hmac_secret: Optional[bytes] = hmac_secret.encode("utf-8")
        else:
            self._hmac_secret = hmac_secret

        self._sequence_counter: int = 0
        self._last_record_hash: Optional[str] = None

    @property
    def last_record_hash(self) -> Optional[str]:
        """Return the SHA-256 digest of the most recently generated record."""
        return self._last_record_hash

    def reset_sequence(self, start_seq: int = 0) -> None:
        """Reset internal sequence counter, e.g. on new session."""
        self._sequence_counter = start_seq
        self._last_record_hash = None

    def generate(
        self,
        input_image: Union[bytes, str, Path],
        model_id: str,
        model_weight_digest: str,
        output: Union[Dict[str, Any], PredictionResult],
        preprocessing_config: Optional[Dict[str, Any]] = None,
        inference_config: Optional[Dict[str, Any]] = None,
        session_id: Optional[Union[str, UUID]] = None,
        sequence_number: Optional[int] = None,
        nonce: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        previous_record_hash: Optional[str] = None,
        enable_chaining: bool = False,
    ) -> InferenceRecord:
        """Generate, canonically serialize, and cryptographically bind an InferenceRecord."""
        # 1. Compute input image hash
        if isinstance(input_image, (str, Path)):
            img_path = Path(input_image)
            if not img_path.is_file():
                raise CVIFCryptographicError(f"Input image file not found: {img_path}")
            input_image_hash = sha256_file(img_path)
        elif isinstance(input_image, (bytes, bytearray, memoryview)):
            input_image_hash = sha256_bytes(bytes(input_image))
        else:
            raise CVIFCryptographicError(f"Unsupported input image type: {type(input_image).__name__}")

        # 2. Compute preprocessing config hash
        prep_cfg = preprocessing_config or {}
        preprocessing_config_hash = sha256_canonical_json(prep_cfg)

        # 3. Handle model output
        if isinstance(output, PredictionResult):
            output_dict = output.model_dump(mode="json")
        elif isinstance(output, dict):
            output_dict = output
        else:
            raise CVIFCryptographicError(f"Unsupported output type: {type(output).__name__}")

        # 4. Handle session and sequence
        effective_session_id = (
            UUID(str(session_id)) if session_id else self.default_session_id
        )

        if sequence_number is not None:
            seq_num = sequence_number
        else:
            seq_num = self._sequence_counter
            self._sequence_counter += 1

        effective_nonce = nonce or uuid4().hex
        effective_timestamp = timestamp or utc_now()

        # 5. Handle hash chaining
        if previous_record_hash is not None:
            chain_hash = previous_record_hash
        elif enable_chaining:
            chain_hash = self._last_record_hash
        else:
            chain_hash = None

        # 6. Instantiate unsigned record
        record = InferenceRecord(
            session_id=effective_session_id,
            producer_id=self.producer_id,
            origin=self.origin,
            input_image_hash=input_image_hash,
            model_id=model_id,
            model_weight_digest=model_weight_digest,
            preprocessing_config_hash=preprocessing_config_hash,
            inference_config=inference_config or {},
            output=output_dict,
            signing_key_id=self.signing_key_id,
            timestamp=effective_timestamp,
            sequence_number=seq_num,
            nonce=effective_nonce,
            previous_record_hash=chain_hash,
            binding_hmac=None,
            signature=None,
        )

        # 7. Compute canonical payload bytes
        canonical_bytes = record.compute_canonical_payload()

        # 8. Apply cryptographic signatures
        if self._private_key is not None:
            record.signature = sign_ed25519(self._private_key, canonical_bytes)

        if self._hmac_secret is not None:
            record.binding_hmac = compute_hmac_sha256(self._hmac_secret, canonical_bytes)

        self._last_record_hash = record.compute_record_hash()
        return record
