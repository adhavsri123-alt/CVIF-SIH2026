"""Unit test suite for Phase 5: Inference Provenance.

Validates:
- Deterministic canonical serialization & float quantization
- Ed25519 digital signature signing & verification
- HMAC-SHA256 symmetric MAC binding & verification
- Tampering matrix (all 11 mutations: input, model, preprocessing, prediction, timestamp, sequence, nonce, session, key, chain, signature)
- Replay matrix (scenarios A-I: exact duplicate, same nonce, sequence regression/duplicate/gap, cross-session, cross-contributor, restart persistence)
- Multi-contributor isolation
- Key lifecycle (unknown, revoked, expired)
- Model & preprocessing substitution
- Hash chain stream verification
- Schema version handling
- InferenceProvenanceOrchestrator execution & audit logging
- Strict air-gap isolation
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import socket
from uuid import uuid4
import pytest

from cvif.analysis.inference_provenance.orchestrator import InferenceProvenanceOrchestrator
from cvif.audit.logger import AuditLogger
from cvif.core.enums import Disposition, KeyStatus, ProvenanceOutcome, SeverityLevel
from cvif.core.schemas import (
    ClassificationOutput,
    DetectionOutput,
    InferenceRecord,
    PredictionResult,
    utc_now,
)
from cvif.crypto.hashing import sha256_bytes, sha256_canonical_json
from cvif.crypto.keystore import KeyStore
from cvif.crypto.signing import generate_ed25519_keypair
from cvif.provenance.canonical import (
    build_canonical_payload_dict,
    canonical_payload_bytes,
    quantize_floats,
)
from cvif.provenance.generator import InferenceProvenanceGenerator
from cvif.provenance.verifier import InferenceProvenanceVerifier
from cvif.storage.database import DatabaseManager


# =====================================================================
# Fixtures
# =====================================================================

@pytest.fixture
def test_keys():
    priv, pub = generate_ed25519_keypair()
    return {"priv": priv, "pub": pub, "key_id": "UAV-SQDN-04-ED25519"}


@pytest.fixture
def populated_keystore(temp_dir: Path, test_keys):
    ks = KeyStore(temp_dir / "truststore.json")
    ks.register_public_key(
        key_id=test_keys["key_id"],
        owner_entity="3rd Tactical Reconnaissance Wing",
        public_key=test_keys["pub"],
    )
    ks.register_hmac_secret(
        key_id="EDGE-SENSOR-HMAC-01",
        owner_entity="Border Surveillance Sensor Alpha",
        secret=b"shared_secret_key_bytes_12345678",
    )
    return ks


@pytest.fixture
def provenance_db(temp_dir: Path):
    db_path = temp_dir / "provenance.db"
    return DatabaseManager(db_path)


# =====================================================================
# 1. Canonicalization & Float Quantization Tests
# =====================================================================

def test_deterministic_canonicalization_and_quantization():
    """Verify that identical semantic records with float noise produce exact same canonical bytes."""
    rec1_output = {
        "detections": [
            {
                "bbox": [0.123456789, 0.234567891, 0.456789012, 0.678901234],
                "confidence": 0.8500000000000001,
                "class_id": 1,
            }
        ]
    }
    rec2_output = {
        "detections": [
            {
                "bbox": [0.123457, 0.234568, 0.456789, 0.678901],
                "confidence": 0.85,
                "class_id": 1,
            }
        ]
    }

    q1 = quantize_floats(rec1_output)
    q2 = quantize_floats(rec2_output)

    # 6 decimals for bbox, 4 for confidence
    assert q1["detections"][0]["bbox"] == [0.123457, 0.234568, 0.456789, 0.678901]
    assert q1["detections"][0]["confidence"] == 0.85
    assert q1 == q2


def test_canonical_payload_bytes_reproducibility():
    """Verify canonical byte stream is bit-for-bit identical across executions."""
    fixed_time = datetime(2026, 9, 19, 12, 0, 0, 123456, tzinfo=timezone.utc)
    fixed_session = uuid4()
    fixed_record_id = uuid4()

    rec1 = InferenceRecord(
        record_id=fixed_record_id,
        session_id=fixed_session,
        input_image_hash="a" * 64,
        model_id="yolo_v8_recon",
        model_weight_digest="b" * 64,
        preprocessing_config_hash="c" * 64,
        inference_config={"conf_thresh": 0.5},
        output={"detections": [{"bbox": [0.1, 0.2, 0.3, 0.4], "confidence": 0.9}]},
        timestamp=fixed_time,
        sequence_number=1,
        nonce="nonce_12345",
        signing_key_id="KEY-01",
    )

    rec2 = InferenceRecord(
        record_id=fixed_record_id,
        session_id=fixed_session,
        input_image_hash="a" * 64,
        model_id="yolo_v8_recon",
        model_weight_digest="b" * 64,
        preprocessing_config_hash="c" * 64,
        inference_config={"conf_thresh": 0.500000001},  # Float variance
        output={"detections": [{"bbox": [0.100000001, 0.2, 0.3, 0.4], "confidence": 0.90001}]},
        timestamp=fixed_time,
        sequence_number=1,
        nonce="nonce_12345",
        signing_key_id="KEY-01",
    )

    bytes1 = rec1.compute_canonical_payload()
    bytes2 = rec2.compute_canonical_payload()

    assert bytes1 == bytes2
    assert rec1.compute_record_hash() == rec2.compute_record_hash()


# =====================================================================
# 2. Mode 1 Generator to Mode 2 Verifier End-to-End
# =====================================================================

def test_ed25519_generation_and_verification_pipeline(populated_keystore, provenance_db, test_keys):
    """Verify Mode 1 record generation and Mode 2 verification with Ed25519."""
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
        producer_id="UAV-04",
    )
    raw_img = b"tactical_aerial_reconnaissance_frame_sample_123"

    record = gen.generate(
        input_image=raw_img,
        model_id="yolo_v8_aerial",
        model_weight_digest="beef" * 16,
        output={"detections": [{"bbox": [0.1, 0.1, 0.5, 0.5], "confidence": 0.95, "class_name": "tank"}]},
        preprocessing_config={"resize": [640, 640], "color": "RGB"},
    )

    assert record.signature is not None
    assert record.binding_hmac is None
    assert record.sequence_number == 0

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    res = verifier.verify_record(record, raw_image=raw_img)

    assert res.is_valid is True
    assert res.status == ProvenanceOutcome.VERIFIED
    assert res.disposition == Disposition.ACCEPT
    assert len(res.findings) == 0


def test_hmac_generation_and_verification_pipeline(populated_keystore, provenance_db):
    """Verify Mode 1 record generation and Mode 2 verification with HMAC-SHA256."""
    gen = InferenceProvenanceGenerator(
        signing_key_id="EDGE-SENSOR-HMAC-01",
        hmac_secret=b"shared_secret_key_bytes_12345678",
        producer_id="BORDER-SENSOR-01",
    )
    raw_img = b"ground_sensor_sample_frame_xyz"

    record = gen.generate(
        input_image=raw_img,
        model_id="resnet18_classifier",
        model_weight_digest="feed" * 16,
        output={"classification": {"class_id": 3, "class_name": "military_truck", "confidence": 0.98}},
    )

    assert record.binding_hmac is not None
    assert record.signature is None

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    res = verifier.verify_record(record, raw_image=raw_img)

    assert res.is_valid is True
    assert res.status == ProvenanceOutcome.VERIFIED
    assert res.disposition == Disposition.ACCEPT


# =====================================================================
# 3. Tampering Test Matrix (All 11 Authenticated Mutations)
# =====================================================================

def _create_valid_record(test_keys):
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
        producer_id="UAV-04",
    )
    return gen.generate(
        input_image=b"clean_input_image",
        model_id="target_model",
        model_weight_digest="11" * 32,
        output={"detections": [{"bbox": [0.1, 0.2, 0.3, 0.4], "confidence": 0.88, "class_name": "radar"}]},
        preprocessing_config={"resize": [640, 640]},
    )


def test_tamper_input_image_hash(populated_keystore, provenance_db, test_keys):
    """1. Mutating input_image_hash must break cryptographic binding."""
    record = _create_valid_record(test_keys)
    record.input_image_hash = "f" * 64

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    res = verifier.verify_record(record)
    assert res.status == ProvenanceOutcome.TAMPERED_OUTPUT
    assert res.disposition == Disposition.QUARANTINE


def test_tamper_model_id_and_digest(populated_keystore, provenance_db, test_keys):
    """2. Mutating model_id or model_weight_digest must break cryptographic binding."""
    record = _create_valid_record(test_keys)
    record.model_id = "malicious_unapproved_model"

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    res = verifier.verify_record(record)
    assert res.status == ProvenanceOutcome.TAMPERED_OUTPUT

    record2 = _create_valid_record(test_keys)
    record2.model_weight_digest = "00" * 32
    res2 = verifier.verify_record(record2)
    assert res2.status == ProvenanceOutcome.TAMPERED_OUTPUT


def test_tamper_preprocessing_hash(populated_keystore, provenance_db, test_keys):
    """3. Mutating preprocessing_config_hash must break cryptographic binding."""
    record = _create_valid_record(test_keys)
    record.preprocessing_config_hash = "dead" * 16

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    res = verifier.verify_record(record)
    assert res.status == ProvenanceOutcome.TAMPERED_OUTPUT


def test_tamper_prediction_outputs(populated_keystore, provenance_db, test_keys):
    """4. Mutating prediction class, confidence, or bbox must break binding."""
    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)

    # A. Change bbox coordinate
    rec_bbox = _create_valid_record(test_keys)
    rec_bbox.output["detections"][0]["bbox"][0] = 0.999
    assert verifier.verify_record(rec_bbox).status == ProvenanceOutcome.TAMPERED_OUTPUT

    # B. Change confidence score
    rec_conf = _create_valid_record(test_keys)
    rec_conf.output["detections"][0]["confidence"] = 0.12
    assert verifier.verify_record(rec_conf).status == ProvenanceOutcome.TAMPERED_OUTPUT

    # C. Change class label
    rec_cls = _create_valid_record(test_keys)
    rec_cls.output["detections"][0]["class_name"] = "civilian_bus"
    assert verifier.verify_record(rec_cls).status == ProvenanceOutcome.TAMPERED_OUTPUT


def test_tamper_timestamp(populated_keystore, provenance_db, test_keys):
    """5. Mutating timestamp must break cryptographic binding (vulnerability fix)."""
    record = _create_valid_record(test_keys)
    record.timestamp = record.timestamp - timedelta(minutes=5)

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    res = verifier.verify_record(record)
    assert res.status == ProvenanceOutcome.TAMPERED_OUTPUT


def test_tamper_sequence_number(populated_keystore, provenance_db, test_keys):
    """6. Mutating sequence number must break cryptographic binding."""
    record = _create_valid_record(test_keys)
    record.sequence_number = 999

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    res = verifier.verify_record(record)
    assert res.status == ProvenanceOutcome.TAMPERED_OUTPUT


def test_tamper_nonce(populated_keystore, provenance_db, test_keys):
    """7. Mutating nonce must break cryptographic binding."""
    record = _create_valid_record(test_keys)
    record.nonce = "tampered_nonce_abcdef"

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    res = verifier.verify_record(record)
    assert res.status == ProvenanceOutcome.TAMPERED_OUTPUT


def test_tamper_session_id(populated_keystore, provenance_db, test_keys):
    """8. Mutating session_id must break cryptographic binding."""
    record = _create_valid_record(test_keys)
    record.session_id = uuid4()

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    res = verifier.verify_record(record)
    assert res.status == ProvenanceOutcome.TAMPERED_OUTPUT


def test_tamper_signing_key_id(populated_keystore, provenance_db, test_keys):
    """9. Mutating signing_key_id must break cryptographic binding."""
    record = _create_valid_record(test_keys)
    record.signing_key_id = "DIFFERENT-KEY-ID"

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    res = verifier.verify_record(record)
    # Fails key resolution or binding
    assert res.status in (ProvenanceOutcome.UNVERIFIED_KEY, ProvenanceOutcome.TAMPERED_OUTPUT)


def test_tamper_previous_record_hash(populated_keystore, provenance_db, test_keys):
    """10. Mutating previous_record_hash must break cryptographic binding."""
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
    )
    record = gen.generate(
        input_image=b"image",
        model_id="m1",
        model_weight_digest="w1",
        output={"class": "a"},
        previous_record_hash="00" * 32,
    )
    record.previous_record_hash = "ff" * 32

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    res = verifier.verify_record(record)
    assert res.status == ProvenanceOutcome.TAMPERED_OUTPUT


def test_tamper_signature_and_raw_image(populated_keystore, provenance_db, test_keys):
    """11. Corrupting signature string or presenting swapped raw image fails verification."""
    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)

    # Corrupt signature string
    rec1 = _create_valid_record(test_keys)
    rec1.signature = rec1.signature[:-4] + "0000"
    assert verifier.verify_record(rec1).status == ProvenanceOutcome.TAMPERED_OUTPUT

    # Swapped raw input image
    rec2 = _create_valid_record(test_keys)
    res2 = verifier.verify_record(rec2, raw_image=b"malicious_swapped_image_bytes")
    assert res2.status == ProvenanceOutcome.TAMPERED_OUTPUT
    assert any(f.threat_id == "IT-4" for f in res2.findings)


# =====================================================================
# 4. Replay Test Matrix (Scenarios A through I)
# =====================================================================

def test_replay_exact_duplicate_rejected(populated_keystore, provenance_db, test_keys):
    """Scenario A: Submitting the same exact record twice is caught on duplicate nonce."""
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
    )
    record = gen.generate(
        input_image=b"replay_frame_1",
        model_id="m",
        model_weight_digest="w",
        output={"score": 0.9},
    )

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)

    # First submission: OK
    res1 = verifier.verify_record(record)
    assert res1.status == ProvenanceOutcome.VERIFIED

    # Second submission: Caught on replay!
    res2 = verifier.verify_record(record)
    assert res2.status == ProvenanceOutcome.REPLAYED_RECORD
    assert res2.disposition == Disposition.QUARANTINE
    assert any("Replayed Nonce" in f.title for f in res2.findings)


def test_replay_same_nonce_altered_record_rejected(populated_keystore, provenance_db, test_keys):
    """Scenario B: Using a known nonce with another signed record is caught on nonce uniqueness."""
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
    )
    fixed_nonce = "fixed_nonce_reuse_attack_123"

    rec1 = gen.generate(
        input_image=b"frame_1",
        model_id="m",
        model_weight_digest="w",
        output={"score": 0.5},
        nonce=fixed_nonce,
    )
    rec2 = gen.generate(
        input_image=b"frame_2",
        model_id="m",
        model_weight_digest="w",
        output={"score": 0.8},
        nonce=fixed_nonce,
    )

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    assert verifier.verify_record(rec1).status == ProvenanceOutcome.VERIFIED

    res2 = verifier.verify_record(rec2)
    assert res2.status == ProvenanceOutcome.REPLAYED_RECORD
    assert any("Replayed Nonce" in f.title for f in res2.findings)


def test_sequence_regression_and_rollback_rejected(populated_keystore, provenance_db, test_keys):
    """Scenarios C, D, E: Sequence rollback or duplicate sequence within session is rejected."""
    session_id = uuid4()
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
        default_session_id=session_id,
    )

    rec0 = gen.generate(b"img0", "m", "w", {"score": 0.1}, sequence_number=0)
    rec1 = gen.generate(b"img1", "m", "w", {"score": 0.2}, sequence_number=1)
    rec2 = gen.generate(b"img2", "m", "w", {"score": 0.3}, sequence_number=2)
    rec_rollback = gen.generate(b"img_old", "m", "w", {"score": 0.15}, sequence_number=1)

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)

    assert verifier.verify_record(rec0).status == ProvenanceOutcome.VERIFIED
    assert verifier.verify_record(rec1).status == ProvenanceOutcome.VERIFIED
    assert verifier.verify_record(rec2).status == ProvenanceOutcome.VERIFIED

    # Re-submitting sequence 1 after sequence 2 is rejected
    res_roll = verifier.verify_record(rec_rollback)
    assert res_roll.status == ProvenanceOutcome.REPLAYED_RECORD
    assert any("Sequence Number Regression" in f.title for f in res_roll.findings)


def test_sequence_gap_detection(populated_keystore, provenance_db, test_keys):
    """Scenario F: Sequence jumps indicate potential packet suppression (IT-5 warning)."""
    session_id = uuid4()
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
        default_session_id=session_id,
    )

    rec0 = gen.generate(b"img0", "m", "w", {"score": 0.1}, sequence_number=0)
    rec5 = gen.generate(b"img5", "m", "w", {"score": 0.5}, sequence_number=5)  # Jump of 4 dropped frames

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    assert verifier.verify_record(rec0).status == ProvenanceOutcome.VERIFIED

    res_gap = verifier.verify_record(rec5)
    assert res_gap.status == ProvenanceOutcome.VERIFIED_WITH_WARNING
    assert res_gap.disposition == Disposition.REVIEW
    assert any(f.threat_id == "IT-5" for f in res_gap.findings)


def test_replay_state_persists_across_restart(temp_dir: Path, test_keys, populated_keystore):
    """Scenario I: Replay and sequence tables persist across DatabaseManager restarts."""
    db_path = temp_dir / "persistent_provenance.db"
    db1 = DatabaseManager(db_path)

    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
    )
    rec = gen.generate(b"persist_img", "m", "w", {"score": 0.99}, sequence_number=10)

    verifier1 = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=db1)
    assert verifier1.verify_record(rec).status == ProvenanceOutcome.VERIFIED

    db1.close()

    # Reopen DB (simulating system restart)
    db2 = DatabaseManager(db_path)
    verifier2 = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=db2)

    # Same record presented after restart must still be rejected as replay
    res_replayed = verifier2.verify_record(rec)
    assert res_replayed.status == ProvenanceOutcome.REPLAYED_RECORD
    db2.close()


# =====================================================================
# 4b. Hardening Regression Tests: Sequence-State Pollution Prevention
# =====================================================================

def _query_db_sequence(db: DatabaseManager, session_id, key_id):
    """Directly query SQLite session_sequences table for current sequence state."""
    with db.transaction() as cur:
        cur.execute(
            "SELECT last_sequence_number FROM session_sequences WHERE session_id = ? AND signing_key_id = ?;",
            (str(session_id), str(key_id)),
        )
        row = cur.fetchone()
        return row["last_sequence_number"] if row else None


def test_regression_mandatory_sequence_state_pollution_prevented(temp_dir: Path, test_keys):
    """MANDATORY REGRESSION TEST: Sequence-state pollution vulnerability fix.
    
    1. Create isolated DB + KeyStore.
    2. Generate valid record: session S, sequence 0, valid signature
       -> VERIFIED, DB sequence = 0
    3. Generate attacker record: same session S, sequence 999999, corrupt/replace signature
       -> TAMPERED_OUTPUT, DB sequence MUST remain 0
    4. Generate legitimate record: same session S, sequence 1, valid signature
       -> VERIFIED, DB sequence = 1
    
    Directly inspects SQLite session_sequences table at each step.
    """
    ks = KeyStore(temp_dir / "reg_truststore.json")
    ks.register_public_key(test_keys["key_id"], "Recon Squadron", test_keys["pub"])
    db = DatabaseManager(temp_dir / "reg_provenance.db")

    session_s = uuid4()
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
        default_session_id=session_s,
    )
    verifier = InferenceProvenanceVerifier(key_store=ks, db_manager=db)

    # Step 1: Valid sequence 0
    rec0 = gen.generate(b"clean_frame_0", "recon_model", "digest_0", {"score": 0.95}, sequence_number=0)
    res0 = verifier.verify_record(rec0)
    assert res0.status == ProvenanceOutcome.VERIFIED
    assert res0.is_valid is True
    assert _query_db_sequence(db, session_s, test_keys["key_id"]) == 0

    # Step 2: Attacker sequence 999999 with corrupt signature
    rec_attacker = gen.generate(
        b"attacker_frame", "recon_model", "digest_0", {"score": 0.10}, sequence_number=999999
    )
    rec_attacker.signature = rec_attacker.signature[:-8] + "00000000"  # Corrupt signature
    res_attacker = verifier.verify_record(rec_attacker)
    assert res_attacker.status == ProvenanceOutcome.TAMPERED_OUTPUT
    assert res_attacker.is_valid is False
    # CRITICAL INVARIANT: DB sequence MUST remain 0!
    assert _query_db_sequence(db, session_s, test_keys["key_id"]) == 0

    # Step 3: Legitimate sequence 1
    rec1 = gen.generate(b"clean_frame_1", "recon_model", "digest_0", {"score": 0.97}, sequence_number=1)
    res1 = verifier.verify_record(rec1)
    assert res1.status == ProvenanceOutcome.VERIFIED
    assert res1.is_valid is True
    # Successfully advanced to 1 without being rejected as REPLAYED_RECORD
    assert _query_db_sequence(db, session_s, test_keys["key_id"]) == 1

    db.close()


def test_regression_variant_a_invalid_signature(temp_dir: Path, test_keys):
    """Variant A: invalid signature + sequence 999999 -> rejected, sequence unchanged."""
    ks = KeyStore(temp_dir / "var_a_ks.json")
    ks.register_public_key(test_keys["key_id"], "Unit", test_keys["pub"])
    db = DatabaseManager(temp_dir / "var_a.db")

    session_s = uuid4()
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
        default_session_id=session_s,
    )
    verifier = InferenceProvenanceVerifier(key_store=ks, db_manager=db)

    # Initialize sequence 0
    rec0 = gen.generate(b"img0", "m", "w", {}, sequence_number=0)
    assert verifier.verify_record(rec0).status == ProvenanceOutcome.VERIFIED
    assert _query_db_sequence(db, session_s, test_keys["key_id"]) == 0

    # Variant A: Corrupted signature
    rec_bad = gen.generate(b"bad", "m", "w", {}, sequence_number=999999)
    rec_bad.signature = "a" * len(rec_bad.signature)
    res_bad = verifier.verify_record(rec_bad)
    assert res_bad.status == ProvenanceOutcome.TAMPERED_OUTPUT
    assert _query_db_sequence(db, session_s, test_keys["key_id"]) == 0

    db.close()


def test_regression_variant_b_missing_signature(temp_dir: Path, test_keys):
    """Variant B: missing signature + sequence 999999 -> rejected, sequence unchanged."""
    ks = KeyStore(temp_dir / "var_b_ks.json")
    ks.register_public_key(test_keys["key_id"], "Unit", test_keys["pub"])
    db = DatabaseManager(temp_dir / "var_b.db")

    session_s = uuid4()
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
        default_session_id=session_s,
    )
    verifier = InferenceProvenanceVerifier(key_store=ks, db_manager=db)

    rec0 = gen.generate(b"img0", "m", "w", {}, sequence_number=0)
    assert verifier.verify_record(rec0).status == ProvenanceOutcome.VERIFIED
    assert _query_db_sequence(db, session_s, test_keys["key_id"]) == 0

    # Variant B: Missing signature
    rec_none = gen.generate(b"bad", "m", "w", {}, sequence_number=999999)
    rec_none.signature = None
    res_none = verifier.verify_record(rec_none)
    assert res_none.status == ProvenanceOutcome.TAMPERED_OUTPUT
    assert _query_db_sequence(db, session_s, test_keys["key_id"]) == 0

    db.close()


def test_regression_variant_c_malformed_signature(temp_dir: Path, test_keys):
    """Variant C: malformed signature + sequence 999999 -> rejected, sequence unchanged."""
    ks = KeyStore(temp_dir / "var_c_ks.json")
    ks.register_public_key(test_keys["key_id"], "Unit", test_keys["pub"])
    db = DatabaseManager(temp_dir / "var_c.db")

    session_s = uuid4()
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
        default_session_id=session_s,
    )
    verifier = InferenceProvenanceVerifier(key_store=ks, db_manager=db)

    rec0 = gen.generate(b"img0", "m", "w", {}, sequence_number=0)
    assert verifier.verify_record(rec0).status == ProvenanceOutcome.VERIFIED
    assert _query_db_sequence(db, session_s, test_keys["key_id"]) == 0

    # Variant C: Malformed short / non-hex signature
    rec_malformed = gen.generate(b"bad", "m", "w", {}, sequence_number=999999)
    rec_malformed.signature = "deadbeef_not_valid_sig"
    res_malformed = verifier.verify_record(rec_malformed)
    assert res_malformed.status == ProvenanceOutcome.TAMPERED_OUTPUT
    assert _query_db_sequence(db, session_s, test_keys["key_id"]) == 0

    db.close()


def test_regression_variant_d_unauthorized_signing_key(temp_dir: Path, test_keys):
    """Variant D: unauthorized signing key + sequence 999999 -> rejected, sequence unchanged."""
    ks = KeyStore(temp_dir / "var_d_ks.json")
    ks.register_public_key(test_keys["key_id"], "Unit", test_keys["pub"])
    db = DatabaseManager(temp_dir / "var_d.db")

    session_s = uuid4()
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
        default_session_id=session_s,
    )
    verifier = InferenceProvenanceVerifier(key_store=ks, db_manager=db)

    rec0 = gen.generate(b"img0", "m", "w", {}, sequence_number=0)
    assert verifier.verify_record(rec0).status == ProvenanceOutcome.VERIFIED
    assert _query_db_sequence(db, session_s, test_keys["key_id"]) == 0

    # Variant D: Unknown unauthorized key
    unauth_priv, _ = generate_ed25519_keypair()
    gen_unauth = InferenceProvenanceGenerator(
        signing_key_id="UNAUTHORIZED-ROGUE-KEY",
        private_key=unauth_priv,
        default_session_id=session_s,
    )
    rec_unauth = gen_unauth.generate(b"bad", "m", "w", {}, sequence_number=999999)
    res_unauth = verifier.verify_record(rec_unauth)
    assert res_unauth.status in (ProvenanceOutcome.UNVERIFIED_KEY, ProvenanceOutcome.TAMPERED_OUTPUT)
    assert _query_db_sequence(db, session_s, test_keys["key_id"]) == 0
    assert _query_db_sequence(db, session_s, "UNAUTHORIZED-ROGUE-KEY") is None

    db.close()


def test_regression_variant_e_full_lifecycle_across_all_invalid_variants(temp_dir: Path, test_keys):
    """Variant E: valid seq 0 -> invalid seq 999999 -> valid seq 1 for multiple adversary packet types."""
    ks = KeyStore(temp_dir / "var_e_ks.json")
    ks.register_public_key(test_keys["key_id"], "Tactical Sqdn", test_keys["pub"])
    db = DatabaseManager(temp_dir / "var_e.db")

    verifier = InferenceProvenanceVerifier(key_store=ks, db_manager=db)

    for i, attack_mode in enumerate(["corrupted_sig", "missing_sig", "malformed_sig", "unauthorized_key"]):
        session_id = uuid4()
        gen = InferenceProvenanceGenerator(
            signing_key_id=test_keys["key_id"],
            private_key=test_keys["priv"],
            default_session_id=session_id,
        )

        # 1. Valid seq 0 accepted
        r0 = gen.generate(b"f0", "m", "w", {}, sequence_number=0)
        assert verifier.verify_record(r0).status == ProvenanceOutcome.VERIFIED
        assert _query_db_sequence(db, session_id, test_keys["key_id"]) == 0

        # 2. Attacker packet rejected, sequence unchanged
        r_att = gen.generate(b"fatt", "m", "w", {}, sequence_number=999999)
        if attack_mode == "corrupted_sig":
            r_att.signature = "00" * 64
        elif attack_mode == "missing_sig":
            r_att.signature = None
        elif attack_mode == "malformed_sig":
            r_att.signature = "malformed_short_string"
        elif attack_mode == "unauthorized_key":
            r_att.signing_key_id = f"UNKNOWN-ATTACKER-KEY-{i}"

        res_att = verifier.verify_record(r_att)
        assert res_att.is_valid is False
        assert _query_db_sequence(db, session_id, test_keys["key_id"]) == 0

        # 3. Legitimate seq 1 accepted
        r1 = gen.generate(b"f1", "m", "w", {}, sequence_number=1)
        res1 = verifier.verify_record(r1)
        assert res1.status == ProvenanceOutcome.VERIFIED
        assert _query_db_sequence(db, session_id, test_keys["key_id"]) == 1

    db.close()


def test_regression_replay_and_nonce_protection_retained(temp_dir: Path, test_keys):
    """Variants F & G: Existing valid replay and nonce protections remain active and robust."""
    ks = KeyStore(temp_dir / "var_fg_ks.json")
    ks.register_public_key(test_keys["key_id"], "Tactical Sqdn", test_keys["pub"])
    db = DatabaseManager(temp_dir / "var_fg.db")

    session_id = uuid4()
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
        default_session_id=session_id,
    )
    verifier = InferenceProvenanceVerifier(key_store=ks, db_manager=db)

    # Valid seq 0
    rec0 = gen.generate(b"f0", "m", "w", {}, sequence_number=0)
    assert verifier.verify_record(rec0).status == ProvenanceOutcome.VERIFIED

    # F1: Replay exact same sequence 0 (duplicate seq regression)
    rec0_dup = gen.generate(b"f0_dup", "m", "w", {}, sequence_number=0)
    res_dup = verifier.verify_record(rec0_dup)
    assert res_dup.status == ProvenanceOutcome.REPLAYED_RECORD
    assert any("Sequence Number Regression" in f.title for f in res_dup.findings)

    # Valid seq 1
    rec1 = gen.generate(b"f1", "m", "w", {}, sequence_number=1)
    assert verifier.verify_record(rec1).status == ProvenanceOutcome.VERIFIED
    assert _query_db_sequence(db, session_id, test_keys["key_id"]) == 1

    # F2: Rollback sequence (submit seq 0 after seq 1)
    rec_rollback = gen.generate(b"f_old", "m", "w", {}, sequence_number=0)
    res_roll = verifier.verify_record(rec_rollback)
    assert res_roll.status == ProvenanceOutcome.REPLAYED_RECORD

    # G: Nonce replay with advancing sequence
    rec2_fixed_nonce = gen.generate(b"f2", "m", "w", {}, sequence_number=2, nonce="REUSED-NONCE-XYZ")
    assert verifier.verify_record(rec2_fixed_nonce).status == ProvenanceOutcome.VERIFIED

    rec3_reused_nonce = gen.generate(b"f3", "m", "w", {}, sequence_number=3, nonce="REUSED-NONCE-XYZ")
    res_reused = verifier.verify_record(rec3_reused_nonce)
    assert res_reused.status == ProvenanceOutcome.REPLAYED_RECORD
    assert any("Replayed Nonce" in f.title for f in res_reused.findings)

    db.close()


# =====================================================================
# 5. Multi-Contributor Isolation
# =====================================================================

def test_multi_contributor_isolation(temp_dir: Path):
    """Verify independent contributor streams do not collide or allow identity substitution."""
    ks = KeyStore(temp_dir / "multi_keystore.json")
    db = DatabaseManager(temp_dir / "multi.db")

    priv_a, pub_a = generate_ed25519_keypair()
    priv_b, pub_b = generate_ed25519_keypair()

    ks.register_public_key("CONTRIBUTOR-A-PUB", "Recon Unit A", pub_a)
    ks.register_public_key("CONTRIBUTOR-B-PUB", "Recon Unit B", pub_b)

    gen_a = InferenceProvenanceGenerator(signing_key_id="CONTRIBUTOR-A-PUB", private_key=priv_a, producer_id="Unit A")
    gen_b = InferenceProvenanceGenerator(signing_key_id="CONTRIBUTOR-B-PUB", private_key=priv_b, producer_id="Unit B")

    shared_session_id = uuid4()
    rec_a = gen_a.generate(b"image_a", "model_x", "weight_x", {"detections": []}, sequence_number=0, session_id=shared_session_id)
    rec_b = gen_b.generate(b"image_b", "model_x", "weight_x", {"detections": []}, sequence_number=0, session_id=shared_session_id)

    verifier = InferenceProvenanceVerifier(key_store=ks, db_manager=db)

    # Both verify cleanly with identical sequence_number=0 because key_ids differ
    assert verifier.verify_record(rec_a).status == ProvenanceOutcome.VERIFIED
    assert verifier.verify_record(rec_b).status == ProvenanceOutcome.VERIFIED

    # Contributor A tries to sign with A's key but claims B's key ID
    spoofed = gen_a.generate(b"image_spoof", "model_x", "weight_x", {"detections": []})
    spoofed.signing_key_id = "CONTRIBUTOR-B-PUB"
    # Fails signature check (signed with A's privkey, verified against B's pubkey)
    assert verifier.verify_record(spoofed).status == ProvenanceOutcome.TAMPERED_OUTPUT


# =====================================================================
# 6. Key Lifecycle Tests
# =====================================================================

def test_unknown_revoked_and_expired_keys(temp_dir: Path):
    """Verify unknown, revoked, and expired keys are cleanly handled."""
    ks = KeyStore(temp_dir / "keys.json")
    priv, pub = generate_ed25519_keypair()

    ks.register_public_key("ACTIVE-KEY", "Entity 1", pub)
    ks.register_public_key(
        "EXPIRED-KEY",
        "Entity 2",
        pub,
        valid_until=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    ks.register_public_key("REVOKED-KEY", "Entity 3", pub)
    ks.revoke_key("REVOKED-KEY")

    verifier = InferenceProvenanceVerifier(key_store=ks)

    # 1. Unknown key
    gen_unk = InferenceProvenanceGenerator(signing_key_id="NON-EXISTENT-KEY", private_key=priv)
    rec_unk = gen_unk.generate(b"img", "m", "w", {})
    res_unk = verifier.verify_record(rec_unk)
    assert res_unk.status == ProvenanceOutcome.UNVERIFIED_KEY
    assert res_unk.disposition == Disposition.REVIEW

    # 2. Expired key
    gen_exp = InferenceProvenanceGenerator(signing_key_id="EXPIRED-KEY", private_key=priv)
    rec_exp = gen_exp.generate(b"img", "m", "w", {})
    res_exp = verifier.verify_record(rec_exp)
    assert res_exp.status == ProvenanceOutcome.EXPIRED_KEY
    assert res_exp.disposition == Disposition.QUARANTINE

    # 3. Revoked key
    gen_rev = InferenceProvenanceGenerator(signing_key_id="REVOKED-KEY", private_key=priv)
    rec_rev = gen_rev.generate(b"img", "m", "w", {})
    res_rev = verifier.verify_record(rec_rev)
    assert res_rev.status == ProvenanceOutcome.EXPIRED_KEY
    assert res_rev.disposition == Disposition.QUARANTINE


# =====================================================================
# 7. Model and Preprocessing Substitution Tests
# =====================================================================

def test_model_and_preprocessing_substitution(populated_keystore, provenance_db, test_keys):
    """Verify IT-2 model and preprocessing divergence against catalog baselines."""
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
    )

    record = gen.generate(
        input_image=b"image",
        model_id="recon_model",
        model_weight_digest="deployed_model_hash_abc",
        output={"score": 0.9},
        preprocessing_config={"resize": [640, 640]},
    )

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)

    # Model weight digest mismatch
    res_model_sub = verifier.verify_record(
        record, registered_model_digest="registered_catalog_hash_xyz"
    )
    assert res_model_sub.status == ProvenanceOutcome.SUBSTITUTED_MODEL
    assert res_model_sub.disposition == Disposition.QUARANTINE
    assert any(f.threat_id == "IT-2" for f in res_model_sub.findings)

    # Preprocessing hash mismatch
    record2 = gen.generate(
        input_image=b"image2",
        model_id="recon_model",
        model_weight_digest="deployed_model_hash_abc",
        output={"score": 0.9},
        preprocessing_config={"resize": [640, 640]},
    )
    res_prep_sub = verifier.verify_record(
        record2,
        registered_model_digest="deployed_model_hash_abc",
        registered_preprocessing_hash="different_preproc_hash_123",
    )
    assert res_prep_sub.status == ProvenanceOutcome.SUBSTITUTED_MODEL
    assert any("Preprocessing Configuration Mismatch" in f.title for f in res_prep_sub.findings)



# =====================================================================
# 8. Hash Chain Stream Continuity Tests
# =====================================================================

def test_hash_chain_stream_verification(populated_keystore, provenance_db, test_keys):
    """Verify sequential records in stream cryptographically bind to previous record hash."""
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
    )

    r1 = gen.generate(b"img1", "m", "w", {"score": 0.1}, enable_chaining=True)
    r2 = gen.generate(b"img2", "m", "w", {"score": 0.2}, enable_chaining=True)
    r3 = gen.generate(b"img3", "m", "w", {"score": 0.3}, enable_chaining=True)

    # R2 references R1's record hash
    assert r2.previous_record_hash == r1.compute_record_hash()
    assert r3.previous_record_hash == r2.compute_record_hash()

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)

    # Verifying R2 expecting R1's hash passes
    assert verifier.verify_record(r2, expected_previous_record_hash=r1.compute_record_hash()).is_valid is True

    # Broken chain: verifying R3 expecting R1's hash (simulating dropped R2) fails
    res_broken = verifier.verify_record(r3, expected_previous_record_hash=r1.compute_record_hash())
    assert res_broken.status == ProvenanceOutcome.TAMPERED_OUTPUT
    assert any("Broken Record Stream Hash Chain Link" in f.title for f in res_broken.findings)


# =====================================================================
# 9. Schema Version Compatibility Tests
# =====================================================================

def test_schema_version_compatibility(populated_keystore, test_keys):
    """Verify unsupported future schema versions fail cleanly."""
    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
    )
    record = gen.generate(b"img", "m", "w", {})
    record.schema_version = "9.9"

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore)
    res = verifier.verify_record(record)
    assert res.status == ProvenanceOutcome.UNSUPPORTED
    assert res.is_valid is False
    assert any(f.threat_id == "IT-SCHEMA-ERR" for f in res.findings)


# =====================================================================
# 10. Orchestrator and Audit Logging Integration
# =====================================================================

def test_orchestrator_execution_and_audit_logging(temp_dir: Path, populated_keystore, provenance_db, test_keys):
    """Verify InferenceProvenanceOrchestrator runs checks, logs events, and produces AnalysisSession."""
    audit_path = temp_dir / "provenance_audit.jsonl"
    logger = AuditLogger(audit_path)

    verifier = InferenceProvenanceVerifier(key_store=populated_keystore, db_manager=provenance_db)
    orchestrator = InferenceProvenanceOrchestrator(
        verifier=verifier,
        audit_logger=logger,
    )

    gen = InferenceProvenanceGenerator(
        signing_key_id=test_keys["key_id"],
        private_key=test_keys["priv"],
    )
    record = gen.generate(b"audit_test_image", "m", "w", {"score": 0.9})

    session = orchestrator.verify_and_analyze(record, operator_id="officer_alpha")

    assert session.status.value == "COMPLETED"
    assert "IT-1" in session.executed_analyses
    assert "IT-2" in session.executed_analyses
    assert "IT-3" in session.executed_analyses

    # Verify audit chain integrity
    audit_res = logger.verify_chain()
    assert audit_res.is_valid is True
    assert audit_res.total_events >= 2


# =====================================================================
# 11. Strict Air-Gap Isolation
# =====================================================================

def test_provenance_strictly_offline(temp_dir: Path, monkeypatch):
    """Verify generation, verification, and database state operate 100% offline with no sockets."""
    def forbidden_socket(*args, **kwargs):
        raise RuntimeError("AIR_GAP_VIOLATION: Attempted socket connection during Phase 5 provenance operations!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    # Run complete Mode 1 + Mode 2 cycle under forbidden socket
    ks = KeyStore(temp_dir / "airgap_ks.json")
    db = DatabaseManager(temp_dir / "airgap.db")

    priv, pub = generate_ed25519_keypair()
    ks.register_public_key("OFFLINE-UAV-KEY", "AirGap Sqdn", pub)

    gen = InferenceProvenanceGenerator(signing_key_id="OFFLINE-UAV-KEY", private_key=priv)
    rec = gen.generate(b"offline_bytes", "offline_model", "offline_weights", {"detections": []})

    verifier = InferenceProvenanceVerifier(key_store=ks, db_manager=db)
    res = verifier.verify_record(rec)

    assert res.is_valid is True
    assert res.status == ProvenanceOutcome.VERIFIED
    db.close()
