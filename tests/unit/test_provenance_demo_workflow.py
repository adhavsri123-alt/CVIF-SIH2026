"""Regression and workflow tests for Inference Provenance Demo Record Generation and Replay-Safe Verification.

Validates specifications 12.A through 12.E:
- A. Fresh record verifies successfully (VERIFIED, is_valid=True, 0 findings, ACCEPT).
- B. Submitting that same record a second time is rejected as replay (REPLAYED_RECORD, is_valid=False, QUARANTINE).
- C. A newly generated record verifies successfully (auto-incrementing sequence, unique nonce).
- D. Tampering with the output still produces TAMPERED_OUTPUT / IT-1 finding.
- E. Replay protection remains permanently enabled and persistent across verification calls.
- API endpoints: POST /provenance/demo-record and POST /provenance/verify end-to-end.
"""

from pathlib import Path
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient

from cvif.api.main import create_app
from cvif.cli.commands.common import RuntimeContext
from cvif.core.config import AppConfig
from cvif.core.enums import Disposition, ProvenanceOutcome, SeverityLevel
from cvif.crypto.keystore import KeyStore
from cvif.provenance.demo import (
    DEMO_KEY_ID,
    DEMO_PRODUCER_ID,
    DEMO_SESSION_ID,
    generate_demo_inference_record,
    get_demo_keypair,
)
from cvif.provenance.verifier import InferenceProvenanceVerifier
from cvif.storage.database import DatabaseManager


@pytest.fixture
def isolated_keystore(tmp_path: Path) -> KeyStore:
    """Isolated keystore with registered demo public key."""
    ks_path = tmp_path / "truststore.json"
    ks = KeyStore(persistence_path=ks_path)
    _, pub_key, key_id, producer_id = get_demo_keypair()
    ks.register_public_key(
        key_id=key_id,
        owner_entity=producer_id,
        public_key=pub_key,
    )
    return ks


@pytest.fixture
def isolated_db(tmp_path: Path) -> DatabaseManager:
    """Isolated SQLite database manager."""
    db_path = tmp_path / "test_catalogue.db"
    return DatabaseManager(db_path)


@pytest.fixture
def verifier(isolated_keystore: KeyStore, isolated_db: DatabaseManager) -> InferenceProvenanceVerifier:
    """Provenance verifier wired to isolated stores."""
    return InferenceProvenanceVerifier(
        key_store=isolated_keystore,
        db_manager=isolated_db,
        tolerance_seconds=3600.0,
    )


# ═══════════════════════════════════════════════════════════════════════
# 1. Regression Tests A through E
# ═══════════════════════════════════════════════════════════════════════

def test_regression_a_fresh_record_verifies_successfully(verifier: InferenceProvenanceVerifier, isolated_db: DatabaseManager):
    """Test A: Fresh record verifies successfully with 0 findings and ACCEPT disposition."""
    record = generate_demo_inference_record(db_manager=isolated_db)
    
    assert record.sequence_number == 1
    assert record.signing_key_id == DEMO_KEY_ID
    assert record.producer_id == DEMO_PRODUCER_ID
    assert record.session_id == DEMO_SESSION_ID
    assert record.signature is not None

    res = verifier.verify_record(record, enforce_replay_checks=True)

    assert res.is_valid is True
    assert res.status == ProvenanceOutcome.VERIFIED
    assert len(res.findings) == 0
    assert res.disposition == Disposition.ACCEPT


def test_regression_b_submitting_same_record_second_time_is_rejected_as_replay(
    verifier: InferenceProvenanceVerifier, isolated_db: DatabaseManager
):
    """Test B: Submitting that same record a second time is strictly rejected as replay attack."""
    record = generate_demo_inference_record(db_manager=isolated_db)
    
    # First verification must succeed
    res1 = verifier.verify_record(record, enforce_replay_checks=True)
    assert res1.is_valid is True
    assert res1.status == ProvenanceOutcome.VERIFIED

    # Second verification of identical payload must fail due to replay defense
    res2 = verifier.verify_record(record, enforce_replay_checks=True)
    assert res2.is_valid is False
    assert res2.status == ProvenanceOutcome.REPLAYED_RECORD
    assert res2.disposition == Disposition.QUARANTINE

    # Must contain both Sequence Regression and Replayed Nonce findings
    threat_ids = [f.threat_id for f in res2.findings]
    assert "IT-3" in threat_ids
    finding_titles = [f.title for f in res2.findings]
    assert any("Sequence Number Regression" in title for title in finding_titles)
    assert any("Replayed Nonce Detected" in title for title in finding_titles)


def test_regression_c_newly_generated_record_verifies_successfully(
    verifier: InferenceProvenanceVerifier, isolated_db: DatabaseManager
):
    """Test C: A newly generated record cleanly verifies after previous record is consumed."""
    # Record 1
    rec1 = generate_demo_inference_record(db_manager=isolated_db)
    res1 = verifier.verify_record(rec1, enforce_replay_checks=True)
    assert res1.is_valid is True
    assert res1.status == ProvenanceOutcome.VERIFIED

    # Replay attempt fails
    res_replay = verifier.verify_record(rec1, enforce_replay_checks=True)
    assert res_replay.is_valid is False

    # Generate Record 2: Must advance sequence and obtain unique nonce
    rec2 = generate_demo_inference_record(db_manager=isolated_db)
    assert rec2.record_id != rec1.record_id
    assert rec2.nonce != rec1.nonce
    assert rec2.sequence_number == rec1.sequence_number + 1

    # Record 2 must verify cleanly
    res2 = verifier.verify_record(rec2, enforce_replay_checks=True)
    assert res2.is_valid is True
    assert res2.status == ProvenanceOutcome.VERIFIED
    assert len(res2.findings) == 0
    assert res2.disposition == Disposition.ACCEPT

    # Generate Record 3: Must continue stream
    rec3 = generate_demo_inference_record(db_manager=isolated_db)
    assert rec3.sequence_number == rec2.sequence_number + 1
    res3 = verifier.verify_record(rec3, enforce_replay_checks=True)
    assert res3.is_valid is True
    assert res3.status == ProvenanceOutcome.VERIFIED


def test_regression_d_tampering_with_output_produces_tamper_finding(
    verifier: InferenceProvenanceVerifier, isolated_db: DatabaseManager
):
    """Test D: Tampering with the output still produces TAMPERED_OUTPUT and IT-1 finding."""
    tampered_rec = generate_demo_inference_record(db_manager=isolated_db, tampered=True)
    
    assert tampered_rec.output["classification"]["confidence"] == 0.9999
    
    res = verifier.verify_record(tampered_rec, enforce_replay_checks=True)
    assert res.is_valid is False
    assert res.status == ProvenanceOutcome.TAMPERED_OUTPUT
    assert res.disposition == Disposition.QUARANTINE
    
    it1_findings = [f for f in res.findings if f.threat_id == "IT-1"]
    assert len(it1_findings) > 0
    assert it1_findings[0].severity == SeverityLevel.CRITICAL
    assert "Invalid Ed25519 Digital Signature" in it1_findings[0].title


def test_regression_e_replay_protection_remains_enabled(
    verifier: InferenceProvenanceVerifier, isolated_db: DatabaseManager
):
    """Test E: Replay protection is permanently enabled; database state persists and is not wiped."""
    rec = generate_demo_inference_record(db_manager=isolated_db)
    verifier.verify_record(rec, enforce_replay_checks=True)

    # Verify directly in SQLite that nonce and sequence state are persisted
    last_seq = isolated_db.get_last_sequence(str(rec.session_id), str(rec.signing_key_id))
    assert last_seq == rec.sequence_number

    # Verify record_nonce_if_new returns False for the same nonce
    is_new = isolated_db.record_nonce_if_new(rec.nonce, str(uuid4()), "2026-09-20T12:00:00Z")
    assert is_new is False

    # Attempting to verify an older or equal sequence number must fail monotonicity
    is_mono, prev_seq = isolated_db.record_sequence_if_monotonic(
        str(rec.session_id), str(rec.signing_key_id), rec.sequence_number, "2026-09-20T12:00:00Z"
    )
    assert is_mono is False
    assert prev_seq == rec.sequence_number


# ═══════════════════════════════════════════════════════════════════════
# 2. API End-to-End Test
# ═══════════════════════════════════════════════════════════════════════

def test_api_demo_record_generation_and_verification_lifecycle(tmp_path: Path):
    """Test full HTTP API lifecycle for /provenance/demo-record and /provenance/verify."""
    cfg = AppConfig()
    cfg = cfg.resolve_paths(tmp_path)
    cfg.api.enable_docs = False
    cfg.api.api_key_enabled = False
    cfg.storage.catalog_db_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.evidence.evidence_dir.mkdir(parents=True, exist_ok=True)
    cfg.keystore.keystore_dir.mkdir(parents=True, exist_ok=True)
    cfg.audit.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    db = DatabaseManager(cfg.storage.catalog_db_path)
    keystore = KeyStore(cfg.keystore.keystore_dir / "truststore.json")

    ctx = RuntimeContext(
        config=cfg,
        db=db,
        audit=None,
        evidence=None,
        keystore=keystore,
    )

    app = create_app(config=cfg)
    app.state.ctx = ctx
    client = TestClient(app, raise_server_exceptions=False)

    # 1. Generate fresh demo record via API
    gen_resp = client.post("/api/v1/provenance/demo-record", json={})
    assert gen_resp.status_code == 200
    gen_data = gen_resp.json()
    assert gen_data["is_tampered"] is False
    assert gen_data["sequence_number"] == 1
    assert "Fresh demo record generated" in gen_data["message"]
    rec1 = gen_data["record"]

    # 2. Verify fresh demo record -> 200, is_valid=True
    verify_resp = client.post("/api/v1/provenance/verify", json={"record": rec1})
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["is_valid"] is True
    assert verify_data["status"] == "VERIFIED"
    assert verify_data["findings_count"] == 0

    # 3. Submit exact same record again -> 200, is_valid=False (REPLAYED_RECORD)
    replay_resp = client.post("/api/v1/provenance/verify", json={"record": rec1})
    assert replay_resp.status_code == 200
    replay_data = replay_resp.json()
    assert replay_data["is_valid"] is False
    assert replay_data["status"] == "REPLAYED_RECORD"
    assert replay_data["findings_count"] == 2

    # 4. Generate next fresh demo record -> auto-increments sequence
    gen_resp2 = client.post("/api/v1/provenance/demo-record", json={})
    assert gen_resp2.status_code == 200
    gen_data2 = gen_resp2.json()
    assert gen_data2["sequence_number"] == 2
    rec2 = gen_data2["record"]

    # 5. Verify next fresh record -> 200, is_valid=True
    verify_resp2 = client.post("/api/v1/provenance/verify", json={"record": rec2})
    assert verify_resp2.status_code == 200
    assert verify_resp2.json()["is_valid"] is True
    assert verify_resp2.json()["status"] == "VERIFIED"

    # 6. Generate tampered record via API
    gen_tampered = client.post("/api/v1/provenance/demo-record", json={"tampered": True})
    assert gen_tampered.status_code == 200
    assert gen_tampered.json()["is_tampered"] is True
    tampered_rec = gen_tampered.json()["record"]

    # 7. Verify tampered record -> 200, is_valid=False, status=TAMPERED_OUTPUT
    verify_tampered = client.post("/api/v1/provenance/verify", json={"record": tampered_rec})
    assert verify_tampered.status_code == 200
    tampered_data = verify_tampered.json()
    assert tampered_data["is_valid"] is False
    assert tampered_data["status"] == "TAMPERED_OUTPUT"
    assert any(f["threat_id"] == "IT-1" for f in tampered_data["findings"])
