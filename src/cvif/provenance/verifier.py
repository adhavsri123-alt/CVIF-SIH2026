"""Mode 2: Inference Provenance Verifier (Assurance Gateway).

Executes the full 8-step forensic verification pipeline over incoming InferenceRecords:
1. Schema & version validation
2. Key resolution against local air-gapped KeyStore
3. Deterministic cryptographic binding verification (Ed25519 & HMAC-SHA256)
4. Input image hash integrity verification
5. Model registry digest cross-referencing
6. Preprocessing configuration cross-referencing
7. Timestamp plausibility & skew validation
8. Replay detection (SQLite unique nonces & strictly monotonic session sequences)
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import UUID, uuid4

from cvif.core.enums import Disposition, EvidenceType, ProvenanceOutcome, SeverityLevel
from cvif.core.schemas import EvidenceRecord, Finding, InferenceRecord, ProvenanceVerificationResult, utc_now
from cvif.crypto.hashing import sha256_bytes, sha256_file
from cvif.crypto.hmac import verify_hmac_sha256
from cvif.crypto.keystore import KeyStore
from cvif.crypto.signing import verify_ed25519
from cvif.storage.database import DatabaseManager


class InferenceProvenanceVerifier:
    """Air-gapped assurance verifier for multi-contributor inference outputs."""

    def __init__(
        self,
        key_store: KeyStore,
        db_manager: Optional[DatabaseManager] = None,
        tolerance_seconds: float = 300.0,
        allow_unverified_keys: bool = False,
    ):
        self.key_store = key_store
        self.db_manager = db_manager
        self.tolerance_seconds = tolerance_seconds
        self.allow_unverified_keys = allow_unverified_keys

    def verify_record(
        self,
        record: InferenceRecord,
        raw_image: Optional[Union[bytes, str, Path]] = None,
        registered_model_digest: Optional[str] = None,
        registered_preprocessing_hash: Optional[str] = None,
        expected_previous_record_hash: Optional[str] = None,
        reference_time: Optional[datetime] = None,
        enforce_replay_checks: bool = True,
    ) -> ProvenanceVerificationResult:
        """Run complete assurance pipeline against an InferenceRecord."""
        findings: List[Finding] = []
        details: Dict[str, Any] = {}
        now = reference_time or utc_now()
        record_uuid = record.record_id
        session_uuid = record.session_id

        # -------------------------------------------------------------
        # Step 1: Schema Version Validation
        # -------------------------------------------------------------
        if record.schema_version != "1.0":
            finding = self._create_finding(
                session_uuid=session_uuid,
                threat_id="IT-SCHEMA-ERR",
                severity=SeverityLevel.HIGH,
                confidence=1.0,
                title="Unsupported Inference Record Schema Version",
                description=f"Record schema version '{record.schema_version}' is unsupported. Expected '1.0'.",
                narrative="Inference record rejected due to incompatible schema specification version.",
            )
            findings.append(finding)
            return ProvenanceVerificationResult(
                status=ProvenanceOutcome.UNSUPPORTED,
                disposition=Disposition.REVIEW,
                is_valid=False,
                record_id=record_uuid,
                session_id=session_uuid,
                signing_key_id=record.signing_key_id,
                producer_id=record.producer_id,
                findings=findings,
                details={"error": "unsupported_schema_version", "version": record.schema_version},
            )

        # -------------------------------------------------------------
        # Step 2: Key Resolution & Status Check
        # -------------------------------------------------------------
        key_id = record.signing_key_id
        is_key_active = False
        key_error_type = None

        if not key_id:
            key_error_type = "MISSING_KEY_ID"
            findings.append(
                self._create_finding(
                    session_uuid=session_uuid,
                    threat_id="IT-KEY-UNKNOWN",
                    severity=SeverityLevel.MEDIUM,
                    confidence=1.0,
                    title="Missing Signing Key ID",
                    description="Record does not declare a signing_key_id; key cannot be resolved in KeyStore.",
                    narrative="Record lacks cryptographic key identity required for trust resolution.",
                )
            )
        else:
            is_valid, msg = self.key_store.check_key_validity(key_id)
            details["key_validity_message"] = msg
            if not is_valid:
                key_rec = self.key_store.get_key_record(key_id)
                if key_rec is None:
                    key_error_type = "UNKNOWN_KEY"
                    findings.append(
                        self._create_finding(
                            session_uuid=session_uuid,
                            threat_id="IT-KEY-UNKNOWN",
                            severity=SeverityLevel.MEDIUM,
                            confidence=1.0,
                            title=f"Unknown Contributor Key '{key_id}'",
                            description=f"Signing key '{key_id}' was not found in the local Trust Store.",
                            narrative=msg,
                        )
                    )
                else:
                    key_error_type = "EXPIRED_OR_REVOKED_KEY"
                    findings.append(
                        self._create_finding(
                            session_uuid=session_uuid,
                            threat_id="IT-KEY-EXPIRED",
                            severity=SeverityLevel.HIGH,
                            confidence=1.0,
                            title=f"Inactive Signing Key '{key_id}'",
                            description=f"Key '{key_id}' status is '{key_rec.status.value}'. Cannot verify active assurance.",
                            narrative=msg,
                        )
                    )
            else:
                is_key_active = True

        # -------------------------------------------------------------
        # Step 3: Cryptographic Binding Verification
        # -------------------------------------------------------------
        binding_verified = False
        sig_checked = False
        hmac_checked = False
        canonical_bytes = record.compute_canonical_payload()

        if record.signature is not None:
            sig_checked = True
            pub_key = self.key_store.get_public_key(key_id) if (key_id and is_key_active) else None
            if pub_key is not None:
                if verify_ed25519(pub_key, canonical_bytes, record.signature):
                    binding_verified = True
                else:
                    findings.append(
                        self._create_finding(
                            session_uuid=session_uuid,
                            threat_id="IT-1",
                            severity=SeverityLevel.CRITICAL,
                            confidence=1.0,
                            title="Invalid Ed25519 Digital Signature (Payload Tampered)",
                            description="Ed25519 cryptographic signature verification failed over canonical payload.",
                            narrative="Cryptographic binding mismatch: output predictions or record parameters were modified post-signing.",
                            recommended_disposition=Disposition.QUARANTINE,
                        )
                    )

        if record.binding_hmac is not None:
            hmac_checked = True
            secret = self.key_store.get_hmac_secret(key_id) if (key_id and is_key_active) else None
            if secret is not None:
                if verify_hmac_sha256(secret, canonical_bytes, record.binding_hmac):
                    binding_verified = True
                else:
                    findings.append(
                        self._create_finding(
                            session_uuid=session_uuid,
                            threat_id="IT-1",
                            severity=SeverityLevel.CRITICAL,
                            confidence=1.0,
                            title="Invalid HMAC-SHA256 Binding (Payload Tampered)",
                            description="HMAC-SHA256 verification failed over canonical payload.",
                            narrative="Cryptographic HMAC mismatch: output predictions or record parameters were modified.",
                            recommended_disposition=Disposition.QUARANTINE,
                        )
                    )

        if not sig_checked and not hmac_checked:
            findings.append(
                self._create_finding(
                    session_uuid=session_uuid,
                    threat_id="IT-1",
                    severity=SeverityLevel.CRITICAL,
                    confidence=1.0,
                    title="No Cryptographic Binding Present",
                    description="Record has neither an Ed25519 signature nor an HMAC-SHA256 binding.",
                    narrative="Record contains no proof of origin or integrity.",
                    recommended_disposition=Disposition.QUARANTINE,
                )
            )

        # -------------------------------------------------------------
        # Step 4: Input Image Integrity Check
        # -------------------------------------------------------------
        if raw_image is not None:
            if isinstance(raw_image, (bytes, bytearray, memoryview)):
                computed_img_hash = sha256_bytes(bytes(raw_image))
            elif isinstance(raw_image, (str, Path)):
                img_p = Path(raw_image)
                computed_img_hash = sha256_file(img_p) if img_p.is_file() else ""
            else:
                computed_img_hash = ""

            if computed_img_hash.lower() != record.input_image_hash.lower():
                findings.append(
                    self._create_finding(
                        session_uuid=session_uuid,
                        threat_id="IT-4",
                        severity=SeverityLevel.CRITICAL,
                        confidence=1.0,
                        title="Input Image Hash Mismatch (Input Tampering / Substitution)",
                        description=(
                            f"Computed input image SHA-256 ({computed_img_hash[:16]}...) does not match "
                            f"record.input_image_hash ({record.input_image_hash[:16]}...)."
                        ),
                        narrative="The raw image presented does not match the image digest bound into the inference record.",
                        recommended_disposition=Disposition.QUARANTINE,
                    )
                )

        # -------------------------------------------------------------
        # Step 5: Model Registry Cross-Reference Check
        # -------------------------------------------------------------
        expected_model_digest = registered_model_digest
        if expected_model_digest is None and self.db_manager is not None:
            asset = self.db_manager.get_asset(record.model_id)
            if asset is not None and asset.hash_manifest.entries:
                expected_model_digest = asset.hash_manifest.entries[0].digest

        if expected_model_digest is not None:
            if record.model_weight_digest.lower() != expected_model_digest.lower():
                findings.append(
                    self._create_finding(
                        session_uuid=session_uuid,
                        threat_id="IT-2",
                        severity=SeverityLevel.HIGH,
                        confidence=1.0,
                        title="Model Weight Digest Mismatch (Model Substitution)",
                        description=(
                            f"Record model_weight_digest ({record.model_weight_digest[:16]}...) does not match "
                            f"registered baseline digest ({expected_model_digest[:16]}...) for model '{record.model_id}'."
                        ),
                        narrative="Inference was performed using an unauthorized or substituted model artifact.",
                        recommended_disposition=Disposition.QUARANTINE,
                    )
                )

        # -------------------------------------------------------------
        # Step 6: Preprocessing Config Cross-Reference Check
        # -------------------------------------------------------------
        if registered_preprocessing_hash is not None:
            if record.preprocessing_config_hash.lower() != registered_preprocessing_hash.lower():
                findings.append(
                    self._create_finding(
                        session_uuid=session_uuid,
                        threat_id="IT-2",
                        severity=SeverityLevel.MEDIUM,
                        confidence=1.0,
                        title="Preprocessing Configuration Mismatch",
                        description=(
                            f"Record preprocessing_config_hash ({record.preprocessing_config_hash[:16]}...) does not match "
                            f"registered baseline hash ({registered_preprocessing_hash[:16]}...)."
                        ),
                        narrative="Image preprocessing parameters diverge from the approved baseline pipeline configuration.",
                        recommended_disposition=Disposition.REVIEW,
                    )
                )

        # -------------------------------------------------------------
        # Step 7: Timestamp Plausibility Check
        # -------------------------------------------------------------
        rec_time = record.timestamp
        if rec_time.tzinfo is None:
            rec_time = rec_time.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        time_delta = abs((now - rec_time).total_seconds())
        details["time_skew_seconds"] = round(time_delta, 3)

        if time_delta > self.tolerance_seconds:
            findings.append(
                self._create_finding(
                    session_uuid=session_uuid,
                    threat_id="IT-3",
                    severity=SeverityLevel.HIGH,
                    confidence=1.0,
                    title="Timestamp Skew Exceeded (Potential Stale / Replayed Record)",
                    description=(
                        f"Record timestamp ({rec_time.isoformat()}) diverges by {time_delta:.1f}s from "
                        f"verifier clock ({now.isoformat()}), exceeding {self.tolerance_seconds}s limit."
                    ),
                    narrative="Record violates allowable air-gapped clock synchronization window.",
                    recommended_disposition=Disposition.REVIEW,
                )
            )

        # -------------------------------------------------------------
        # Step 8: Hash Chain Linkage Verification
        # -------------------------------------------------------------
        if expected_previous_record_hash is not None:
            if record.previous_record_hash != expected_previous_record_hash:
                findings.append(
                    self._create_finding(
                        session_uuid=session_uuid,
                        threat_id="IT-1",
                        severity=SeverityLevel.CRITICAL,
                        confidence=1.0,
                        title="Broken Record Stream Hash Chain Link",
                        description=(
                            f"Record previous_record_hash ({record.previous_record_hash}) does not match "
                            f"expected stream tip ({expected_previous_record_hash})."
                        ),
                        narrative="Inference record stream continuity broken: prior records omitted or reordered.",
                        recommended_disposition=Disposition.QUARANTINE,
                    )
                )

        # -------------------------------------------------------------
        # Step 9: Replay & Monotonicity State Checks (SQLite)
        # -------------------------------------------------------------
        if enforce_replay_checks and self.db_manager is not None and key_id:
            # Query existing sequence state without mutating persistent storage
            last_seq = self.db_manager.get_last_sequence(str(session_uuid), str(key_id))
            details["previous_sequence"] = last_seq

            # Security Invariant: A record MUST NOT modify persistent sequence state unless:
            # 1. The record's cryptographic binding has been successfully verified.
            # 2. The signing key is valid/authorized.
            # 3. The record has passed the required cryptographic integrity checks.
            # An invalid, forged, malformed, or unauthenticated record MUST NEVER advance session_sequences.
            is_crypto_verified = (
                binding_verified
                and is_key_active
                and key_error_type is None
                and not any(f.threat_id in ("IT-1", "IT-4") for f in findings)
                and not any(f.severity == SeverityLevel.CRITICAL for f in findings)
            )

            if is_crypto_verified:
                # Check Sequence Monotonicity & atomically advance sequence state
                is_monotonic, prev_seq = self.db_manager.record_sequence_if_monotonic(
                    session_id=str(session_uuid),
                    signing_key_id=str(key_id),
                    sequence_number=record.sequence_number,
                    timestamp_iso=rec_time.isoformat(),
                )
                details["previous_sequence"] = prev_seq

                if not is_monotonic:
                    findings.append(
                        self._create_finding(
                            session_uuid=session_uuid,
                            threat_id="IT-3",
                            severity=SeverityLevel.HIGH,
                            confidence=1.0,
                            title="Sequence Number Regression (Replayed Record)",
                            description=(
                                f"Record sequence {record.sequence_number} <= previous sequence {prev_seq} "
                                f"for session '{session_uuid}' and key '{key_id}'."
                            ),
                            narrative="Sequence number rollback or duplicate detected within operational session stream.",
                            recommended_disposition=Disposition.QUARANTINE,
                        )
                    )
                elif prev_seq is not None and record.sequence_number > (prev_seq + 1):
                    gap_size = record.sequence_number - prev_seq - 1
                    findings.append(
                        self._create_finding(
                            session_uuid=session_uuid,
                            threat_id="IT-5",
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.85,
                            title=f"Sequence Gap Detected ({gap_size} Records Dropped)",
                            description=(
                                f"Sequence jumped from {prev_seq} to {record.sequence_number} "
                                f"(gap of {gap_size} records in session '{session_uuid}')."
                            ),
                            narrative="Potential selective frame suppression or network packet drop in tactical stream.",
                            recommended_disposition=Disposition.REVIEW,
                        )
                    )

            # Check Nonce Uniqueness
            is_new_nonce = self.db_manager.record_nonce_if_new(
                nonce=record.nonce,
                record_id=str(record_uuid),
                timestamp_iso=rec_time.isoformat(),
            )
            if not is_new_nonce:
                findings.append(
                    self._create_finding(
                        session_uuid=session_uuid,
                        threat_id="IT-3",
                        severity=SeverityLevel.CRITICAL,
                        confidence=1.0,
                        title="Replayed Nonce Detected (Replay Attack)",
                        description=f"Nonce '{record.nonce}' has already been observed in the system.",
                        narrative="Identical nonce observed previously; indicates duplicate submission or replay attack.",
                        recommended_disposition=Disposition.QUARANTINE,
                    )
                )

        # -------------------------------------------------------------
        # Determine Final Outcome & Disposition
        # -------------------------------------------------------------
        status = self._synthesize_status(findings, key_error_type, binding_verified)
        disposition = self._determine_disposition(status, findings)
        is_valid = status in (ProvenanceOutcome.VERIFIED, ProvenanceOutcome.VERIFIED_WITH_WARNING)

        return ProvenanceVerificationResult(
            status=status,
            disposition=disposition,
            is_valid=is_valid,
            record_id=record_uuid,
            session_id=session_uuid,
            signing_key_id=key_id,
            producer_id=record.producer_id,
            findings=findings,
            details=details,
            verified_at=now,
        )

    def _synthesize_status(
        self,
        findings: List[Finding],
        key_error_type: Optional[str],
        binding_verified: bool,
    ) -> ProvenanceOutcome:
        """Derive overall provenance status from accumulated findings."""
        threat_ids = [f.threat_id for f in findings]
        titles = [f.title for f in findings]

        if any(f.threat_id in ("IT-1", "IT-4") for f in findings):
            return ProvenanceOutcome.TAMPERED_OUTPUT
        if any("Replayed Nonce" in t or "Sequence Number Regression" in t or "Timestamp Skew" in t for t in titles):
            return ProvenanceOutcome.REPLAYED_RECORD
        if "IT-2" in threat_ids:
            return ProvenanceOutcome.SUBSTITUTED_MODEL
        if key_error_type == "EXPIRED_OR_REVOKED_KEY":
            return ProvenanceOutcome.EXPIRED_KEY
        if key_error_type in ("UNKNOWN_KEY", "MISSING_KEY_ID"):
            return ProvenanceOutcome.UNVERIFIED_KEY
        if "IT-5" in threat_ids:
            return ProvenanceOutcome.VERIFIED_WITH_WARNING

        return ProvenanceOutcome.VERIFIED

    def _determine_disposition(
        self, status: ProvenanceOutcome, findings: List[Finding]
    ) -> Disposition:
        """Map verification outcome to recommended analyst disposition."""
        if status in (
            ProvenanceOutcome.TAMPERED_OUTPUT,
            ProvenanceOutcome.REPLAYED_RECORD,
            ProvenanceOutcome.SUBSTITUTED_MODEL,
            ProvenanceOutcome.EXPIRED_KEY,
        ):
            return Disposition.QUARANTINE
        if status in (
            ProvenanceOutcome.UNVERIFIED_KEY,
            ProvenanceOutcome.UNSUPPORTED,
            ProvenanceOutcome.VERIFIED_WITH_WARNING,
        ):
            return Disposition.REVIEW
        return Disposition.ACCEPT

    def _create_finding(
        self,
        session_uuid: UUID,
        threat_id: str,
        severity: SeverityLevel,
        confidence: float,
        title: str,
        description: str,
        narrative: str,
        recommended_disposition: Disposition = Disposition.REVIEW,
    ) -> Finding:
        finding_id = uuid4()
        evidence = EvidenceRecord(
            finding_id=finding_id,
            session_id=session_uuid,
            evidence_type=EvidenceType.CRYPTOGRAPHIC,
            narrative=narrative,
            methodology="Inference Provenance Cryptographic Pipeline Verification",
            reproducibility_info={"threat_id": threat_id},
        )
        return Finding(
            finding_id=finding_id,
            asset_id=session_uuid,
            session_id=session_uuid,
            threat_id=threat_id,
            category="INFERENCE_PROVENANCE",
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            evidence_ids=[evidence.evidence_id],
            recommended_disposition=recommended_disposition,
            limitations=["Verification relies on local trust store state and registered model catalogs"],
        )
