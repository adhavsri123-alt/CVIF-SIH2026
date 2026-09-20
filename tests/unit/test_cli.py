"""Phase 9/12 — Comprehensive Command-Line Interface Test Matrix (Categories A–AC).

Validates:
- Typer application dispatch across all audited commands
- Centralized deterministic exit codes (0, 1, 2, 3, 10, 11, 12, 13, 14, 15, 20, 21)
- Machine-readable JSON output and strict stdout/stderr separation
- Subsystem integrations (Dataset, Model, Provenance, Shift, Assurance, Evidence, Audit)
- Path traversal defenses and model safety scanning enforcement
- Air-gap offline confinement and anti-stub behavioral sensitivity
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import socket
from typing import Dict, List
from uuid import uuid4
import pytest
from typer.testing import CliRunner

from cvif.analysis.assurance.orchestrator import AssuranceOrchestrator
from cvif.audit.logger import AuditLogger
from cvif.cli.exit_codes import (
    EXIT_ASSURANCE_QUARANTINE,
    EXIT_ASSURANCE_REVIEW,
    EXIT_CLI_ERROR,
    EXIT_CONFIG_ERROR,
    EXIT_DATA_INTEGRITY_FINDING,
    EXIT_MODEL_INTEGRITY_FINDING,
    EXIT_NOT_FOUND,
    EXIT_PROVENANCE_FAILED,
    EXIT_SHIFT_DETECTED,
    EXIT_SUCCESS,
    EXIT_TAMPER_DETECTED,
    EXIT_VALIDATION_ERROR,
)
from cvif.cli.main import app
from cvif.core.enums import (
    AssetType,
    AuditEventType,
    Disposition,
    EvidenceType,
    ModelTask,
    ProvenanceOutcome,
    SeverityLevel,
)
from cvif.core.schemas import (
    AnalysisSession,
    AssetRegistration,
    EvidenceRecord,
    Finding,
    HashManifest,
    InferenceRecord,
    utc_now,
)
from cvif.crypto.hashing import sha256_bytes
from cvif.crypto.keystore import KeyStore
from cvif.crypto.signing import generate_ed25519_keypair
from cvif.evidence.store import EvidenceStore
from cvif.provenance.generator import InferenceProvenanceGenerator
from cvif.storage.database import DatabaseManager


@pytest.fixture
def runner():
    """Typer CLI test runner."""
    return CliRunner()


@pytest.fixture
def test_env(temp_dir: Path):
    """Isolated environment with dedicated config, database, evidence store, and audit log."""
    env_dir = temp_dir / "cli_env"
    env_dir.mkdir(parents=True, exist_ok=True)

    db_path = env_dir / "catalogue.db"
    audit_path = env_dir / "audit.jsonl"
    ev_dir = env_dir / "evidence_store"
    keys_dir = env_dir / "keys"

    db = DatabaseManager(db_path)
    audit = AuditLogger(audit_path)
    evidence = EvidenceStore(base_dir=ev_dir, db_manager=db, audit_logger=audit, enforce_content=True)
    keystore = KeyStore(persistence_path=keys_dir / "truststore.json")

    config_content = f"""
system:
  offline_mode: true
  air_gapped: true
storage:
  data_dir: "{env_dir.as_posix()}"
  catalog_db_path: "{db_path.as_posix()}"
  filestore_dir: "{(env_dir / 'assets').as_posix()}"
audit:
  audit_dir: "{env_dir.as_posix()}"
  audit_log_path: "{audit_path.as_posix()}"
keystore:
  keystore_dir: "{keys_dir.as_posix()}"
evidence:
  evidence_dir: "{ev_dir.as_posix()}"
"""
    config_file = env_dir / "cvif_config.yaml"
    config_file.write_text(config_content.strip(), encoding="utf-8")

    yield {
        "dir": env_dir,
        "config_file": config_file,
        "db": db,
        "audit": audit,
        "evidence": evidence,
        "keystore": keystore,
    }

    evidence.close()
    db.close()


# =====================================================================
# Category A & B & C: CLI Starts, Version, and Help
# =====================================================================
def test_category_a_cli_starts(runner):
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "Computer Vision Integrity Assurance Framework" in res.output


def test_category_b_version_commands(runner):
    # Top-level --version
    res_flag = runner.invoke(app, ["--version"])
    assert res_flag.exit_code == 0
    assert "cvif version" in res_flag.output

    # cvif version
    res_cmd = runner.invoke(app, ["version"])
    assert res_cmd.exit_code == 0
    assert "Framework Version" in res_cmd.output

    # cvif version --json
    res_json = runner.invoke(app, ["version", "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.output)
    assert data["version"] == "0.1.0"
    assert data["air_gap_enforced"] is True


def test_category_c_subcommands_help(runner):
    subcommands = ["dataset", "data", "model", "provenance", "shift", "assess", "evidence", "audit", "status", "version"]
    for sub in subcommands:
        res = runner.invoke(app, [sub, "--help"])
        assert res.exit_code == 0, f"Failed --help for subcommand: {sub}"
        assert "Usage:" in res.output or "Options" in res.output


# =====================================================================
# Category D & E: Invalid Command and Invalid Arguments
# =====================================================================
def test_category_d_invalid_command(runner):
    res = runner.invoke(app, ["nonexistent-command"])
    assert res.exit_code != 0


def test_category_e_missing_required_argument(runner):
    # assess requires --session-id
    res = runner.invoke(app, ["assess"])
    assert res.exit_code != 0
    assert "Missing option" in res.output or "Usage:" in res.output


# =====================================================================
# Category F & G: Missing Files and Path Traversal
# =====================================================================
def test_category_f_missing_file_handling(runner, test_env):
    res = runner.invoke(app, [
        "model", "scan-safety",
        "--model-path", str(test_env["dir"] / "nonexistent_model.pt"),
        "--config", str(test_env["config_file"]),
    ])
    assert res.exit_code == EXIT_CLI_ERROR


def test_category_g_path_traversal_defense(runner, test_env):
    res = runner.invoke(app, [
        "dataset", "ingest",
        "--data-dir", "../../../etc/shadow",
        "--config", str(test_env["config_file"]),
    ])
    assert res.exit_code == EXIT_CLI_ERROR


# =====================================================================
# Category H, I, J: Status & Audit Commands
# =====================================================================
def test_category_h_status_command(runner, test_env):
    res = runner.invoke(app, ["status", "--config", str(test_env["config_file"]), "--json"])
    assert res.exit_code == EXIT_SUCCESS
    data = json.loads(res.output)
    assert data["status"] == "HEALTHY"
    assert data["database"]["accessible"] is True


def test_category_i_audit_verify_valid(runner, test_env):
    # Log an event
    test_env["audit"].log_event(
        event_type=AuditEventType.SYSTEM_STARTED,
        actor="test_runner",
        details={"mode": "test"},
    )
    res = runner.invoke(app, ["audit", "verify", "--config", str(test_env["config_file"]), "--json"])
    assert res.exit_code == EXIT_SUCCESS
    data = json.loads(res.output)
    assert data["verified"] is True
    assert data["status"] == "VALID"


def test_category_j_audit_verify_tampered(runner, test_env):
    test_env["audit"].log_event(event_type=AuditEventType.SYSTEM_STARTED, actor="test")
    test_env["audit"].log_event(event_type=AuditEventType.ANALYSIS_STARTED, actor="test")

    # Maliciously alter audit file
    log_file = test_env["audit"].log_path
    lines = log_file.read_text(encoding="utf-8").splitlines()
    first_evt = json.loads(lines[0])
    first_evt["actor"] = "malicious_hacker"
    lines[0] = json.dumps(first_evt)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = runner.invoke(app, ["audit", "verify", "--config", str(test_env["config_file"]), "--json"])
    assert res.exit_code == EXIT_TAMPER_DETECTED
    data = json.loads(res.output)
    assert data["verified"] is False
    assert data["status"] == "TAMPER_DETECTED"


# =====================================================================
# Category K, L, M: Evidence Store CLI Commands
# =====================================================================
def test_category_k_evidence_list_and_get(runner, test_env):
    store: EvidenceStore = test_env["evidence"]
    sess_id = uuid4()
    finding_id = uuid4()

    rec = EvidenceRecord(
        finding_id=finding_id,
        session_id=sess_id,
        evidence_type=EvidenceType.STATISTICAL,
        metrics={"test_metric": 0.99},
        narrative="Test narrative",
        methodology="Test method",
    )
    store.save_evidence(rec)

    # List evidence
    res_list = runner.invoke(app, [
        "evidence", "list",
        "--session-id", str(sess_id),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    assert res_list.exit_code == EXIT_SUCCESS
    items = json.loads(res_list.output)
    assert len(items) == 1
    assert items[0]["evidence_id"] == str(rec.evidence_id)

    # Get evidence
    res_get = runner.invoke(app, [
        "evidence", "get",
        "--id", str(rec.evidence_id),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    assert res_get.exit_code == EXIT_SUCCESS
    got_rec = json.loads(res_get.output)
    assert got_rec["evidence_id"] == str(rec.evidence_id)
    assert got_rec["metrics"]["test_metric"] == 0.99


def test_category_l_evidence_tamper_detection(runner, test_env):
    store: EvidenceStore = test_env["evidence"]
    sess_id = uuid4()
    rec = EvidenceRecord(
        finding_id=uuid4(),
        session_id=sess_id,
        evidence_type=EvidenceType.STATISTICAL,
        metrics={"score": 0.5},
        narrative="Original",
        methodology="Test",
    )
    saved_path = store.save_evidence(rec)

    # Tamper file on disk directly
    saved_path.write_text('{"tampered": true}', encoding="utf-8")

    res = runner.invoke(app, [
        "evidence", "get",
        "--id", str(rec.evidence_id),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    # Must fail closed with tamper exit code 20
    assert res.exit_code == EXIT_TAMPER_DETECTED


def test_category_m_evidence_verify_and_export(runner, test_env):
    store: EvidenceStore = test_env["evidence"]
    sess_id = uuid4()
    rec = EvidenceRecord(
        finding_id=uuid4(),
        session_id=sess_id,
        evidence_type=EvidenceType.STATISTICAL,
        metrics={"score": 0.85},
        narrative="Exportable evidence",
        methodology="Method",
    )
    store.save_evidence(rec)

    # Verify store
    res_ver = runner.invoke(app, [
        "evidence", "verify",
        "--session-id", str(sess_id),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    assert res_ver.exit_code == EXIT_SUCCESS
    assert json.loads(res_ver.output)["is_consistent"] is True

    # Export evidence bundle
    export_zip = test_env["dir"] / "exported_session.cvif"
    res_exp = runner.invoke(app, [
        "evidence", "export",
        "--session-id", str(sess_id),
        "--output", str(export_zip),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    assert res_exp.exit_code == EXIT_SUCCESS
    assert export_zip.is_file()
    assert json.loads(res_exp.output)["total_records"] == 1


# =====================================================================
# Category N, O, P: Model Commands & Safety Pre-Scan
# =====================================================================
def test_category_n_model_scan_safety_clean(runner, test_env):
    model_file = test_env["dir"] / "dummy_weights.bin"
    model_file.write_bytes(b"\x00" * 2048)

    res = runner.invoke(app, [
        "model", "scan-safety",
        "--model-path", str(model_file),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    assert res.exit_code == EXIT_SUCCESS
    data = json.loads(res.output)
    assert data["is_safe"] is True


def test_category_o_model_scan_safety_malicious_opcode(runner, test_env):
    model_file = test_env["dir"] / "malicious.pt"
    # Inject dangerous pickle opcode
    model_file.write_bytes(b"cposix\nsystem\n(S'rm -rf /'\ntR.")

    res = runner.invoke(app, [
        "model", "scan-safety",
        "--model-path", str(model_file),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    assert res.exit_code == EXIT_MODEL_INTEGRITY_FINDING
    data = json.loads(res.output)
    assert data["is_safe"] is False
    assert len(data["errors"]) > 0


def test_category_p_model_scan_clean(runner, test_env):
    model_file = test_env["dir"] / "clean_model.bin"
    model_file.write_bytes(b"MODEL_WEIGHT_BYTES_CLEAN")

    res = runner.invoke(app, [
        "model", "scan",
        "--model-path", str(model_file),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    assert res.exit_code == EXIT_SUCCESS
    data = json.loads(res.output)
    assert data["status"] == "COMPLETED"


# =====================================================================
# Category Q & R: Provenance Verification CLI
# =====================================================================
def test_category_q_provenance_verify_valid(runner, test_env):
    keystore: KeyStore = test_env["keystore"]
    priv, pub = generate_ed25519_keypair()
    keystore.register_public_key(
        key_id="key-operator-1",
        owner_entity="Unit-HQ",
        public_key=pub,
    )

    image_path = test_env["dir"] / "sample.jpg"
    image_bytes = b"\xFF\xD8\xFF\xE0\x00\x10JFIF" + b"\x00" * 64
    image_path.write_bytes(image_bytes)
    image_hash = sha256_bytes(image_bytes)

    generator = InferenceProvenanceGenerator(
        signing_key_id="key-operator-1",
        private_key=priv,
        producer_id="Unit-HQ",
    )

    record = generator.generate(
        input_image=image_bytes,
        model_id="resnet18-test",
        model_weight_digest="0" * 64,
        output={"predictions": [{"label": "vehicle", "confidence": 0.96}]},
        session_id=uuid4(),
        sequence_number=1,
    )

    rec_file = test_env["dir"] / "inference_record.json"
    rec_file.write_text(record.to_canonical_json(), encoding="utf-8")

    res = runner.invoke(app, [
        "provenance", "verify",
        "--record-file", str(rec_file),
        "--raw-image", str(image_path),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    assert res.exit_code == EXIT_SUCCESS
    data = json.loads(res.output)
    assert data["is_verified"] is True
    assert data["status"] == ProvenanceOutcome.VERIFIED.value


def test_category_r_provenance_verify_invalid(runner, test_env):
    rec_file = test_env["dir"] / "invalid_record.json"
    # Create record with tampered signature and unregistered key
    rec_dict = {
        "record_id": str(uuid4()),
        "session_id": str(uuid4()),
        "producer_id": "Unknown",
        "signing_key_id": "unregistered-key",
        "input_image_hash": "a" * 64,
        "model_id": "resnet18-test",
        "model_weight_digest": "0" * 64,
        "preprocessing_config_hash": "0" * 64,
        "output": {"predictions": []},
        "nonce": "nonce-12345",
        "sequence_number": 1,
        "signature": "00" * 64,
        "timestamp": utc_now().isoformat(),
        "schema_version": "1.0",
    }
    rec_file.write_text(json.dumps(rec_dict), encoding="utf-8")

    res = runner.invoke(app, [
        "provenance", "verify",
        "--record-file", str(rec_file),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    assert res.exit_code == EXIT_PROVENANCE_FAILED
    data = json.loads(res.output)
    assert data["is_verified"] is False


# =====================================================================
# Category S, T, U: Assurance Assessment CLI Verdicts (ACCEPT, REVIEW, QUARANTINE)
# =====================================================================
def test_category_s_assess_verdict_accept(runner, test_env):
    db: DatabaseManager = test_env["db"]
    sess_id = uuid4()
    asset_id = uuid4()

    db.save_asset(
        AssetRegistration(
            asset_id=asset_id,
            asset_type=AssetType.MODEL,
            format="bin",
            total_size_bytes=1024,
            hash_manifest=HashManifest(),
        )
    )

    # Create session with zero findings
    session = AnalysisSession(
        session_id=sess_id,
        asset_id=asset_id,
        findings=[],
    )
    db.save_session(session)

    res = runner.invoke(app, [
        "assess",
        "--session-id", str(sess_id),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    assert res.exit_code == EXIT_SUCCESS
    data = json.loads(res.output)
    assert data["disposition"] == "ACCEPT"
    assert data["composite_risk_score"] == 0.0


def test_category_t_assess_verdict_review(runner, test_env):
    db: DatabaseManager = test_env["db"]
    sess_id = uuid4()
    asset_id = uuid4()

    db.save_asset(
        AssetRegistration(
            asset_id=asset_id,
            asset_type=AssetType.MODEL,
            format="bin",
            total_size_bytes=1024,
            hash_manifest=HashManifest(),
        )
    )

    # Finding with recommended_disposition=REVIEW
    finding = Finding(
        finding_id=uuid4(),
        asset_id=asset_id,
        session_id=sess_id,
        threat_id="MT-2",
        category="MODEL_INTEGRITY",
        severity=SeverityLevel.MEDIUM,
        confidence=0.85,
        title="Significant parameter modification",
        description="Weight divergence detected",
        recommended_disposition=Disposition.REVIEW,
    )
    session = AnalysisSession(
        session_id=sess_id,
        asset_id=asset_id,
        findings=[finding],
    )
    db.save_session(session)

    res = runner.invoke(app, [
        "assess",
        "--session-id", str(sess_id),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    assert res.exit_code == EXIT_ASSURANCE_REVIEW
    data = json.loads(res.output)
    assert data["disposition"] == "REVIEW"


def test_category_u_assess_verdict_quarantine_veto(runner, test_env):
    db: DatabaseManager = test_env["db"]
    sess_id = uuid4()
    asset_id = uuid4()

    db.save_asset(
        AssetRegistration(
            asset_id=asset_id,
            asset_type=AssetType.MODEL,
            format="bin",
            total_size_bytes=1024,
            hash_manifest=HashManifest(),
        )
    )

    # Critical finding triggers automatic Critical Veto -> QUARANTINE
    finding = Finding(
        finding_id=uuid4(),
        asset_id=asset_id,
        session_id=sess_id,
        threat_id="MT-3",
        category="MODEL_INTEGRITY",
        severity=SeverityLevel.CRITICAL,
        confidence=0.95,
        title="Backdoor backdoor detected",
        description="Trigger reconstruction identified high-density activation cluster",
    )
    session = AnalysisSession(
        session_id=sess_id,
        asset_id=asset_id,
        findings=[finding],
    )
    db.save_session(session)

    res = runner.invoke(app, [
        "assess",
        "--session-id", str(sess_id),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    assert res.exit_code == EXIT_ASSURANCE_QUARANTINE
    data = json.loads(res.output)
    assert data["disposition"] == "QUARANTINE"
    assert "CRITICAL VETO" in data["summary"]


# =====================================================================
# Category V & W: Not Found and Config Errors
# =====================================================================
def test_category_v_assess_session_not_found(runner, test_env):
    random_uuid = uuid4()
    res = runner.invoke(app, [
        "assess",
        "--session-id", str(random_uuid),
        "--config", str(test_env["config_file"]),
        "--json",
    ])
    assert res.exit_code == EXIT_NOT_FOUND


def test_category_w_config_error(runner, temp_dir):
    bad_config = temp_dir / "bad_config.yaml"
    bad_config.write_text(":::malformed:yaml:content [unclosed", encoding="utf-8")

    res = runner.invoke(app, [
        "status",
        "--config", str(bad_config),
        "--json",
    ])
    assert res.exit_code == EXIT_CONFIG_ERROR


# =====================================================================
# Category X: Strict Air-Gap Socket Blocking
# =====================================================================
def test_category_x_air_gap_socket_blocking(runner, monkeypatch):
    def blocked_socket(*args, **kwargs):
        raise RuntimeError("Blocked network access attempted in air-gapped test")

    monkeypatch.setattr(socket, "socket", blocked_socket)
    monkeypatch.setattr(socket, "create_connection", blocked_socket)

    res = runner.invoke(app, ["version", "--json"])
    assert res.exit_code == EXIT_SUCCESS
    data = json.loads(res.output)
    assert data["air_gap_enforced"] is True


# =====================================================================
# Category Y: Anti-Stub Behavioral Sensitivity
# =====================================================================
def test_category_y_anti_stub_behavioral_sensitivity(runner, test_env):
    db: DatabaseManager = test_env["db"]
    sess_id = uuid4()
    asset_id = uuid4()

    db.save_asset(
        AssetRegistration(
            asset_id=asset_id,
            asset_type=AssetType.MODEL,
            format="bin",
            total_size_bytes=1024,
            hash_manifest=HashManifest(),
        )
    )

    # Run assess with 0 findings -> clean 0.0
    session1 = AnalysisSession(session_id=sess_id, asset_id=asset_id, findings=[])
    db.save_session(session1)

    res1 = runner.invoke(app, ["assess", "--session-id", str(sess_id), "--config", str(test_env["config_file"]), "--json"])
    score1 = json.loads(res1.output)["composite_risk_score"]

    # Now add finding -> score must change
    session1.findings = [
        Finding(
            asset_id=asset_id,
            session_id=sess_id,
            threat_id="DT-1",
            category="DATA_INTEGRITY",
            severity=SeverityLevel.HIGH,
            confidence=0.8,
            title="Trigger injected",
            description="High frequency artifact",
        )
    ]
    db.save_session(session1)

    res2 = runner.invoke(app, ["assess", "--session-id", str(sess_id), "--config", str(test_env["config_file"]), "--json"])
    score2 = json.loads(res2.output)["composite_risk_score"]

    assert score1 != score2, "Anti-stub failure: composite risk score did not change when findings changed!"


def test_cli_serve_help(runner: CliRunner):
    """Verify serve command displays help text."""
    res = runner.invoke(app, ["serve", "--help"])
    assert res.exit_code == 0
    assert "Start the CVIF REST API server" in res.output


def test_cli_serve_remote_bind_prohibited(runner: CliRunner, test_env: Dict[str, Path]):
    """Verify binding to 0.0.0.0 is blocked when allow_remote_binding is false."""
    res = runner.invoke(
        app,
        ["serve", "--host", "0.0.0.0", "--config", str(test_env["config_file"])],
    )
    assert res.exit_code == EXIT_CONFIG_ERROR
    assert "blocked by security policy" in res.output


def test_cli_serve_invokes_uvicorn(runner: CliRunner, test_env: Dict[str, Path], monkeypatch):
    """Verify serve command launches uvicorn with configured host and port."""
    from unittest.mock import MagicMock
    mock_run = MagicMock()
    monkeypatch.setattr("uvicorn.run", mock_run)

    res = runner.invoke(
        app,
        ["serve", "--host", "127.0.0.1", "--port", "8000", "--config", str(test_env["config_file"])],
    )
    assert res.exit_code == 0
    assert mock_run.called
    call_kwargs = mock_run.call_args[1]
    assert call_kwargs["host"] == "127.0.0.1"
    assert call_kwargs["port"] == 8000
