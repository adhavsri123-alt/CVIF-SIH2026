"""Comprehensive unit and API integration tests for Integrity Lineage (Specifications 1 to 10).

Covers:
1. No active session (HTTP 404 handled cleanly).
2. Empty / incomplete session (INCOMPLETE / NOT VERIFIED, stages show NOT RUN).
3. Fully populated clean session (VERIFIED across complete lineage).
4. Real verified inference (Ed25519 signature verified, bound digest matches).
5. Tampered inference (IT-1 CRITICAL finding, Inference = TAMPERED, Lineage != VERIFIED).
6. Unsupported MT-3 (prerequisites unavailable, MT-3 UNSUPPORTED, LIMITED COVERAGE).
7. Actual evidence retrieval (real counts and records retrieved from store/database).
8. Assurance REVIEW (moderate findings lead to REVIEW disposition and status).
9. Assurance QUARANTINE (critical veto leads to QUARANTINE disposition and status).
10. Model mismatch and dynamic verification (no hardcoded/fabricated results).
"""

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4
import pytest
from fastapi.testclient import TestClient

from cvif.api.main import create_app
from cvif.audit.logger import AuditLogger
from cvif.cli.commands.common import RuntimeContext
from cvif.core.config import AppConfig
from cvif.core.enums import AssetType, Disposition, SeverityLevel
from cvif.core.schemas import (
    AnalysisSession,
    AssetFileManifestEntry,
    AssetRegistration,
    AssuranceVerdict,
    Finding,
    HashManifest,
    SessionStatus,
)
from cvif.crypto.keystore import KeyStore
from cvif.evidence.store import EvidenceStore
from cvif.provenance.demo import (
    DEMO_KEY_ID,
    DEMO_MODEL_WEIGHT_DIGEST,
    DEMO_PRODUCER_ID,
    generate_demo_inference_record,
    get_demo_keypair,
)
from cvif.storage.database import DatabaseManager


def make_test_asset(
    asset_id: UUID,
    asset_type: AssetType = AssetType.MODEL,
    fmt: str = "pytorch",
    digest: str = "c4bc3123a4d849a892e44b5885b8c081c6200aad4690f52eaa646c6ec2057d48",
) -> AssetRegistration:
    """Helper to create and register valid AssetRegistration satisfying foreign key constraints."""
    return AssetRegistration(
        asset_id=asset_id,
        asset_type=asset_type,
        format=fmt,
        file_paths=["file.bin"],
        hash_manifest=HashManifest(entries=[
            AssetFileManifestEntry(path="file.bin", digest=digest, size_bytes=1024)
        ]),
        total_size_bytes=1024,
    )


@pytest.fixture
def mock_runtime_env(tmp_path: Path):
    """Set up isolated DB, truststore, and audit log for lineage testing."""
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
    _, pub_key, key_id, producer_id = get_demo_keypair()
    keystore.register_public_key(
        key_id=key_id,
        owner_entity=producer_id,
        public_key=pub_key,
    )

    audit_logger = AuditLogger(cfg.audit.audit_log_path, auto_verify_on_init=False)
    evidence_store = EvidenceStore(cfg.evidence.evidence_dir, db_manager=db)

    ctx = RuntimeContext(
        config=cfg,
        db=db,
        audit=audit_logger,
        evidence=evidence_store,
        keystore=keystore,
    )

    app = create_app(config=cfg, serve_frontend=False)
    app.state.ctx = ctx
    from cvif.api.dependencies import get_runtime_context
    app.dependency_overrides[get_runtime_context] = lambda: ctx
    client = TestClient(app, raise_server_exceptions=False)
    return {
        "client": client,
        "db": db,
        "keystore": keystore,
        "cfg": cfg,
        "tmp_path": tmp_path,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: No active session (404 Not Found)
# ─────────────────────────────────────────────────────────────────────────────
def test_lineage_no_active_session(mock_runtime_env):
    """Test 1: Querying a non-existent session returns 404 without inventing data."""
    client = mock_runtime_env["client"]
    non_existent = str(uuid4())

    resp = client.get(f"/api/v1/lineage/session/{non_existent}")
    assert resp.status_code == 404
    data = resp.json()
    assert "not found" in data["detail"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: Empty / incomplete session
# ─────────────────────────────────────────────────────────────────────────────
def test_lineage_empty_incomplete_session(mock_runtime_env):
    """Test 2: Empty session shows INCOMPLETE / NOT VERIFIED and unexecuted stages as NOT RUN."""
    client = mock_runtime_env["client"]
    db = mock_runtime_env["db"]

    sess_id = uuid4()
    asset_id = uuid4()
    db.save_asset(make_test_asset(asset_id))

    session = AnalysisSession(
        session_id=sess_id,
        asset_id=asset_id,
        status=SessionStatus.INITIALIZING,
        requested_analyses=[],
        executed_analyses=[],
        skipped_analyses=[],
        findings=[],
    )
    db.save_session(session)

    resp = client.get(f"/api/v1/lineage/session/{sess_id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["session_id"] == str(sess_id)
    assert data["overall_status"] == "INCOMPLETE / NOT VERIFIED"
    assert data["dataset"]["status"] == "NOT RUN"
    assert data["model"]["status"] == "NOT RUN"
    assert data["inference"]["status"] == "NOT RUN"
    assert data["distribution"]["status"] == "NOT RUN"
    assert data["evidence"]["status"] == "NOT RUN"
    assert data["assurance"]["status"] == "NOT RUN"


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: Fully populated clean session
# ─────────────────────────────────────────────────────────────────────────────
def test_lineage_fully_populated_verified_session(mock_runtime_env):
    """Test 3: Fully executed clean session results in overall VERIFIED status."""
    client = mock_runtime_env["client"]
    db = mock_runtime_env["db"]

    sess_id = uuid4()
    asset_id = uuid4()
    model_digest = "c4bc3123a4d849a892e44b5885b8c081c6200aad4690f52eaa646c6ec2057d48"

    db.save_asset(make_test_asset(asset_id, digest=model_digest))

    session = AnalysisSession(
        session_id=sess_id,
        asset_id=asset_id,
        status=SessionStatus.COMPLETED,
        requested_analyses=["MT-1", "MT-2", "MT-4", "INFERENCE_PROVENANCE", "DISTRIBUTION_SHIFT"],
        executed_analyses=["MT-1", "MT-2", "MT-4", "INFERENCE_PROVENANCE", "DISTRIBUTION_SHIFT"],
        skipped_analyses=[],
        findings=[],
        execution_environment={
            "model_id": "VisionClassifierAlpha",
            "model_digest": model_digest,
            "overall_distance": 0.02,
        },
    )
    db.save_session(session)

    db.save_provenance_record(
        record_id=str(uuid4()),
        session_id=str(sess_id),
        model_id="VisionClassifierAlpha",
        model_weight_digest=model_digest,
        input_image_hash="abc1234567890",
        signing_key_id=DEMO_KEY_ID,
        producer_id=DEMO_PRODUCER_ID,
        is_valid=True,
        status="VERIFIED",
    )

    db.save_evidence_record(
        evidence_id=str(uuid4()),
        session_id=str(sess_id),
        finding_id=str(uuid4()),
        evidence_type="CRYPTOGRAPHIC",
        content_hash="deadbeef1234",
        file_path="evidence/rec1.json",
        schema_version="1.0",
        record_json="{}",
    )

    verdict = AssuranceVerdict(
        asset_id=asset_id,
        session_id=sess_id,
        composite_risk_score=0.0,
        disposition=Disposition.ACCEPT,
        summary="Clean assurance assessment: all pipeline components verified intact.",
        contributing_finding_ids=[],
        unsupported_checks=[],
    )
    db.save_verdict(verdict)

    resp = client.get(f"/api/v1/lineage/session/{sess_id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["overall_status"] == "VERIFIED"
    assert data["model"]["status"] == "VERIFIED"
    assert data["model"]["model_digest"] == model_digest
    assert data["inference"]["status"] == "VERIFIED"
    assert data["inference"]["model_mismatch"] is False
    assert data["assurance"]["status"] == "VERIFIED"
    assert data["assurance"]["disposition"] == "ACCEPT"


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: Real verified inference
# ─────────────────────────────────────────────────────────────────────────────
def test_lineage_real_verified_inference(mock_runtime_env):
    """Test 4: Real legitimately signed InferenceRecord verifies and displays VERIFIED in lineage."""
    client = mock_runtime_env["client"]
    db = mock_runtime_env["db"]

    sess_id = uuid4()
    asset_id = uuid4()
    db.save_asset(make_test_asset(asset_id))

    session = AnalysisSession(
        session_id=sess_id,
        asset_id=asset_id,
        status=SessionStatus.COMPLETED,
        executed_analyses=["INFERENCE_PROVENANCE"],
    )
    db.save_session(session)

    rec = generate_demo_inference_record(db_manager=db, session_id=sess_id)
    verify_resp = client.post("/api/v1/provenance/verify", json={"record": rec.model_dump(mode="json")})
    assert verify_resp.status_code == 200
    assert verify_resp.json()["status"] == "VERIFIED"
    assert verify_resp.json()["is_valid"] is True

    lineage_resp = client.get(f"/api/v1/lineage/session/{sess_id}")
    assert lineage_resp.status_code == 200
    data = lineage_resp.json()

    assert data["inference"]["status"] == "VERIFIED"
    assert data["inference"]["is_valid"] is True
    assert data["inference"]["is_tampered"] is False
    assert data["inference"]["bound_model_digest"] == DEMO_MODEL_WEIGHT_DIGEST
    assert data["inference"]["producer_id"] == DEMO_PRODUCER_ID


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: Tampered inference record (IT-1 CRITICAL veto)
# ─────────────────────────────────────────────────────────────────────────────
def test_lineage_tampered_inference_propagation(mock_runtime_env):
    """Test 5: Tampered inference record produces IT-1, status TAMPERED, and propagates failure to lineage."""
    client = mock_runtime_env["client"]
    db = mock_runtime_env["db"]

    sess_id = uuid4()
    asset_id = uuid4()
    db.save_asset(make_test_asset(asset_id))

    session = AnalysisSession(
        session_id=sess_id,
        asset_id=asset_id,
        status=SessionStatus.COMPLETED,
        executed_analyses=["INFERENCE_PROVENANCE"],
    )
    db.save_session(session)

    tampered_rec = generate_demo_inference_record(db_manager=db, session_id=sess_id, tampered=True)
    verify_resp = client.post("/api/v1/provenance/verify", json={"record": tampered_rec.model_dump(mode="json")})
    assert verify_resp.status_code == 200
    assert verify_resp.json()["status"] == "TAMPERED_OUTPUT"
    assert verify_resp.json()["is_valid"] is False

    lineage_resp = client.get(f"/api/v1/lineage/session/{sess_id}")
    assert lineage_resp.status_code == 200
    data = lineage_resp.json()

    assert data["inference"]["status"] == "FAILED / TAMPERED"
    assert data["inference"]["is_tampered"] is True
    assert data["inference"]["verification_state"] == "TAMPERED_OUTPUT"
    assert data["overall_status"] == "FAILED / QUARANTINE"
    assert "tampered" in data["summary"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# Test 6: Unsupported MT-3 capability
# ─────────────────────────────────────────────────────────────────────────────
def test_lineage_unsupported_mt3(mock_runtime_env):
    """Test 6: Unsupported MT-3 is explicitly recorded with reason and not converted to PASS."""
    client = mock_runtime_env["client"]
    db = mock_runtime_env["db"]

    sess_id = uuid4()
    asset_id = uuid4()
    db.save_asset(make_test_asset(asset_id))

    session = AnalysisSession(
        session_id=sess_id,
        asset_id=asset_id,
        status=SessionStatus.COMPLETED,
        executed_analyses=["MT-1", "MT-2"],
        skipped_analyses=[
            {
                "analysis_id": "MT-3",
                "reason": "Gradient access unavailable for black-box model weights",
            }
        ],
        findings=[],
        execution_environment={"model_id": "BlackBoxModel"},
    )
    db.save_session(session)

    resp = client.get(f"/api/v1/lineage/session/{sess_id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["model"]["status"] == "REVIEW"
    assert len(data["model"]["unsupported_checks"]) == 1
    unsupported = data["model"]["unsupported_checks"][0]
    assert unsupported["check_id"] == "MT-3"
    assert "Gradient access unavailable" in unsupported["reason"]
    assert data["overall_status"] == "LIMITED COVERAGE"
    assert "limited coverage" in data["summary"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# Test 7: Actual evidence retrieval
# ─────────────────────────────────────────────────────────────────────────────
def test_lineage_actual_evidence_retrieval(mock_runtime_env):
    """Test 7: Real persisted evidence records are counted and retrieved from SQLite index."""
    client = mock_runtime_env["client"]
    db = mock_runtime_env["db"]

    sess_id = uuid4()
    asset_id = uuid4()
    db.save_asset(make_test_asset(asset_id))

    session = AnalysisSession(
        session_id=sess_id,
        asset_id=asset_id,
        status=SessionStatus.COMPLETED,
    )
    db.save_session(session)

    for ev_type, hsh in [("CRYPTOGRAPHIC", "hash1"), ("STATISTICAL", "hash2"), ("ARTIFACT", "hash3")]:
        db.save_evidence_record(
            evidence_id=str(uuid4()),
            session_id=str(sess_id),
            finding_id=str(uuid4()),
            evidence_type=ev_type,
            content_hash=hsh,
            file_path=f"evidence/{hsh}.json",
            schema_version="1.0",
            record_json="{}",
        )

    resp = client.get(f"/api/v1/lineage/session/{sess_id}")
    assert resp.status_code == 200
    data = resp.json()

    ev = data["evidence"]
    assert ev["status"] == "VERIFIED"
    assert ev["total_records"] == 3
    assert ev["cryptographic_records"] == 1
    assert ev["statistical_records"] == 1
    assert ev["artifact_records"] == 1
    assert len(ev["records"]) == 3


# ─────────────────────────────────────────────────────────────────────────────
# Test 8: Assurance REVIEW
# ─────────────────────────────────────────────────────────────────────────────
def test_lineage_assurance_review(mock_runtime_env):
    """Test 8: Session with non-critical findings synthesizes REVIEW verdict and lineage status."""
    client = mock_runtime_env["client"]
    db = mock_runtime_env["db"]

    sess_id = uuid4()
    asset_id = uuid4()
    db.save_asset(make_test_asset(asset_id))

    session = AnalysisSession(
        session_id=sess_id,
        asset_id=asset_id,
        status=SessionStatus.COMPLETED,
        executed_analyses=["DT-1", "DT-2"],
    )
    db.save_session(session)

    finding = Finding(
        finding_id=uuid4(),
        asset_id=asset_id,
        session_id=sess_id,
        threat_id="DT-2",
        category="DATA_INTEGRITY",
        severity=SeverityLevel.LOW,
        confidence=0.55,
        title="Minor Label Noise Detected",
        description="Low-confidence class ambiguity in small subset",
        recommended_disposition=Disposition.REVIEW,
    )
    db.save_finding(finding)

    session.findings = [finding]
    db.save_session(session)

    verdict = AssuranceVerdict(
        asset_id=asset_id,
        session_id=sess_id,
        composite_risk_score=0.25,
        disposition=Disposition.REVIEW,
        summary="Review required due to low-severity label noise in training set.",
        contributing_finding_ids=[finding.finding_id],
        unsupported_checks=[],
    )
    db.save_verdict(verdict)

    resp = client.get(f"/api/v1/lineage/session/{sess_id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["assurance"]["status"] == "REVIEW"
    assert data["assurance"]["disposition"] == "REVIEW"
    assert data["overall_status"] == "FINDINGS / REVIEW"
    assert "finding" in data["summary"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# Test 9: Assurance QUARANTINE
# ─────────────────────────────────────────────────────────────────────────────
def test_lineage_assurance_quarantine(mock_runtime_env):
    """Test 9: Session with critical veto finding enforces QUARANTINE and FAILED / QUARANTINE lineage."""
    client = mock_runtime_env["client"]
    db = mock_runtime_env["db"]

    sess_id = uuid4()
    asset_id = uuid4()
    db.save_asset(make_test_asset(asset_id))

    session = AnalysisSession(
        session_id=sess_id,
        asset_id=asset_id,
        status=SessionStatus.COMPLETED,
        executed_analyses=["MT-1", "MT-3"],
    )
    db.save_session(session)

    critical_finding = Finding(
        finding_id=uuid4(),
        asset_id=asset_id,
        session_id=sess_id,
        threat_id="MT-3",
        category="MODEL_INTEGRITY",
        severity=SeverityLevel.CRITICAL,
        confidence=0.99,
        title="Trojan Backdoor Trigger Identified",
        description="Neural Cleanse detected backdoored trigger pattern",
        recommended_disposition=Disposition.QUARANTINE,
    )
    db.save_finding(critical_finding)

    session.findings = [critical_finding]
    db.save_session(session)

    verdict = AssuranceVerdict(
        asset_id=asset_id,
        session_id=sess_id,
        composite_risk_score=0.95,
        disposition=Disposition.QUARANTINE,
        summary="Weakest-Link Veto: Trojan backdoor detected in candidate weights.",
        contributing_finding_ids=[critical_finding.finding_id],
        unsupported_checks=[],
    )
    db.save_verdict(verdict)

    resp = client.get(f"/api/v1/lineage/session/{sess_id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["assurance"]["status"] == "FAILED / TAMPERED"
    assert data["assurance"]["disposition"] == "QUARANTINE"
    assert data["overall_status"] == "FAILED / QUARANTINE"
    assert "quarantine" in data["summary"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# Test 10: Model Mismatch & Dynamic Verification (No Fabrication)
# ─────────────────────────────────────────────────────────────────────────────
def test_lineage_model_mismatch_detection(mock_runtime_env):
    """Test 10: Model mismatch between model candidate and inference digest is explicitly flagged."""
    client = mock_runtime_env["client"]
    db = mock_runtime_env["db"]

    sess_id = uuid4()
    asset_id = uuid4()
    candidate_model_digest = "aaaa1111222233334444555566667777888899990000aaaabbbbccccddddeeee"
    different_inference_digest = "ffff9999888877776666555544443333222211110000ffffbbbbccccddddeeee"

    db.save_asset(make_test_asset(asset_id, digest=candidate_model_digest))

    session = AnalysisSession(
        session_id=sess_id,
        asset_id=asset_id,
        status=SessionStatus.COMPLETED,
        executed_analyses=["MT-1", "INFERENCE_PROVENANCE"],
        execution_environment={"model_digest": candidate_model_digest},
    )
    db.save_session(session)

    db.save_provenance_record(
        record_id=str(uuid4()),
        session_id=str(sess_id),
        model_id="SubstitutedModel",
        model_weight_digest=different_inference_digest,
        input_image_hash="inputhash123",
        signing_key_id=DEMO_KEY_ID,
        producer_id=DEMO_PRODUCER_ID,
        is_valid=True,
        status="VERIFIED",
    )

    resp = client.post("/api/v1/lineage/verify", json={"session_id": str(sess_id)})
    assert resp.status_code == 200
    data = resp.json()

    assert data["inference"]["model_mismatch"] is True
    assert data["inference"]["status"] == "FAILED / TAMPERED"
    assert data["overall_status"] == "FAILED / QUARANTINE"
    assert "mismatch" in data["summary"].lower()

    model_inference_dep = next(d for d in data["dependencies"] if d["source"] == "MODEL" and d["target"] == "INFERENCE")
    assert model_inference_dep["is_valid"] is False
    assert "MISMATCH" in model_inference_dep["description"]
