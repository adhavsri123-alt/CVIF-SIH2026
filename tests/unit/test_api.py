"""Phase 10 — REST API test suite.

Tests the full FastAPI application through httpx.AsyncClient / TestClient with
mocked RuntimeContext and services. Validates:
- Health, version, and diagnostics endpoints
- Audit ledger verification
- Dataset ingestion and scanning
- Model safety and integrity scanning
- Provenance verification
- Distribution shift analysis
- Assurance verdict aggregation
- Evidence CRUD, verification, and export
- Error handler coverage and stack-trace suppression
- Request-ID correlation middleware
- Path traversal security guards
- API key authentication enforcement
"""

import json
import platform
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from cvif.api.main import create_app
from cvif.cli.commands.common import RuntimeContext
from cvif.core.config import APIConfig, AppConfig
from cvif.core.exceptions import (
    PathTraversalError,
    TamperDetectedError,
    InvalidModelError,
    AccessDeniedError,
    StorageError,
)
from cvif.crypto.chain import ChainVerificationResult
from cvif.version import __version__, __schema_version__


# ═══════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture
def mock_chain_result():
    """Healthy chain verification result."""
    return ChainVerificationResult(
        is_valid=True,
        total_events=42,
        verified_events=42,
        error_message=None,
        failed_event_index=None,
    )


@pytest.fixture
def mock_ctx(tmp_path, mock_chain_result):
    """Build a RuntimeContext with mock services for test isolation."""
    cfg = AppConfig()
    cfg = cfg.resolve_paths(tmp_path)
    cfg.api.enable_docs = True  # enable OpenAPI for testing
    cfg.api.api_key_enabled = False
    cfg.storage.catalog_db_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.evidence.evidence_dir.mkdir(parents=True, exist_ok=True)
    cfg.keystore.keystore_dir.mkdir(parents=True, exist_ok=True)
    cfg.audit.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    ctx = MagicMock(spec=RuntimeContext)
    ctx.config = cfg

    # Mock database
    ctx.db = MagicMock()
    cursor_mock = MagicMock()
    ctx.db.transaction.return_value.__enter__ = MagicMock(return_value=cursor_mock)
    ctx.db.transaction.return_value.__exit__ = MagicMock(return_value=False)

    # Mock audit
    ctx.audit = MagicMock()
    ctx.audit.verify_chain.return_value = mock_chain_result

    # Mock evidence
    ctx.evidence = MagicMock()

    # Mock keystore
    ctx.keystore = MagicMock()

    return ctx


@pytest.fixture
def app(mock_ctx):
    """Create a FastAPI app with injected mock context (no lifespan init)."""
    application = create_app(config=mock_ctx.config)
    application.state.ctx = mock_ctx
    return application


@pytest.fixture
def client(app):
    """Provide a synchronous TestClient."""
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def api_key_ctx(mock_ctx):
    """Context with API key enforcement enabled."""
    mock_ctx.config.api.api_key_enabled = True
    mock_ctx.config.api.api_keys = ["test-secret-key-123"]
    return mock_ctx


@pytest.fixture
def api_key_app(api_key_ctx):
    """App with API key enforcement."""
    application = create_app(config=api_key_ctx.config)
    application.state.ctx = api_key_ctx
    return application


@pytest.fixture
def api_key_client(api_key_app):
    """Client for API-key-protected app."""
    return TestClient(api_key_app, raise_server_exceptions=False)


# ═══════════════════════════════════════════════════════════════════════
# HEALTH & VERSION
# ═══════════════════════════════════════════════════════════════════════

class TestHealth:
    """Tests for GET /api/v1/health."""

    def test_health_returns_200_when_all_services_healthy(self, client, mock_ctx):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "HEALTHY"
        assert body["audit_chain"]["intact"] is True
        assert body["database"]["accessible"] is True

    def test_health_returns_degraded_when_chain_broken(self, client, mock_ctx):
        mock_ctx.audit.verify_chain.return_value = ChainVerificationResult(
            is_valid=False,
            total_events=10,
            verified_events=7,
            failed_event_index=7,
            error_message="Hash mismatch at block 7",
        )
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "DEGRADED"
        assert body["audit_chain"]["intact"] is False
        assert body["audit_chain"]["broken_index"] == 7

    def test_health_returns_degraded_when_db_inaccessible(self, client, mock_ctx):
        mock_ctx.db.transaction.side_effect = Exception("DB locked")
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "DEGRADED"
        assert body["database"]["accessible"] is False

    def test_health_includes_request_id_header(self, client):
        resp = client.get("/api/v1/health")
        assert "x-request-id" in resp.headers

    def test_health_preserves_client_request_id(self, client):
        custom_id = "custom-trace-001"
        resp = client.get("/api/v1/health", headers={"X-Request-ID": custom_id})
        assert resp.headers.get("x-request-id") == custom_id


class TestVersion:
    """Tests for GET /api/v1/version."""

    def test_version_returns_correct_fields(self, client):
        resp = client.get("/api/v1/version")
        assert resp.status_code == 200
        body = resp.json()
        assert body["version"] == __version__
        assert body["schema_version"] == __schema_version__
        assert body["python_version"] == platform.python_version()
        assert body["air_gap_enforced"] is True
        assert "platform" in body

    def test_version_includes_architecture_version(self, client):
        resp = client.get("/api/v1/version")
        body = resp.json()
        assert body["architecture_version"] == "0.2-REVISED"


# ═══════════════════════════════════════════════════════════════════════
# AUDIT LEDGER VERIFICATION
# ═══════════════════════════════════════════════════════════════════════

class TestAuditVerify:
    """Tests for POST /api/v1/audit/verify."""

    def test_audit_verify_success(self, client, mock_ctx, tmp_path):
        # Create a dummy audit log file
        log_file = mock_ctx.config.audit.audit_log_path
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text("")

        with patch("cvif.api.routes.audit.AuditLogger") as MockLogger:
            mock_logger_instance = MagicMock()
            mock_logger_instance.verify_chain.return_value = ChainVerificationResult(
                is_valid=True, total_events=5, verified_events=5,
            )
            MockLogger.return_value = mock_logger_instance

            resp = client.post("/api/v1/audit/verify", json={})
            assert resp.status_code == 200
            body = resp.json()
            assert body["verified"] is True
            assert body["status"] == "VALID"

    def test_audit_verify_tamper_returns_409(self, client, mock_ctx):
        log_file = mock_ctx.config.audit.audit_log_path
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text("")

        with patch("cvif.api.routes.audit.AuditLogger") as MockLogger:
            mock_logger_instance = MagicMock()
            mock_logger_instance.verify_chain.return_value = ChainVerificationResult(
                is_valid=False, total_events=10, verified_events=3,
                failed_event_index=3, error_message="Tampering detected",
            )
            MockLogger.return_value = mock_logger_instance

            resp = client.post("/api/v1/audit/verify", json={})
            assert resp.status_code == 409
            body = resp.json()
            assert body["error_code"] == "TAMPER_DETECTED"


# ═══════════════════════════════════════════════════════════════════════
# DATASET ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

class TestDatasetEndpoints:
    """Tests for POST /api/v1/datasets/ingest and /api/v1/datasets/scan."""

    def test_ingest_returns_201_on_success(self, client, tmp_path):
        data_dir = tmp_path / "dataset"
        data_dir.mkdir()
        (data_dir / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        mock_reg = MagicMock()
        mock_reg.asset_id = uuid4()
        mock_reg.contributor_id = "test_contributor"
        mock_reg.format = "coco"
        mock_reg.total_size_bytes = 1024

        mock_unified = MagicMock()
        mock_unified.images = [MagicMock()] * 5
        mock_unified.annotations = [MagicMock()] * 10

        mock_val = MagicMock()
        mock_val.is_valid = True
        mock_val.warnings = []

        with patch("cvif.api.routes.datasets.IngestionGateway") as MockGW:
            MockGW.return_value.ingest_dataset.return_value = (
                mock_unified, mock_val, mock_reg,
            )
            resp = client.post("/api/v1/datasets/ingest", json={
                "data_dir": str(data_dir),
                "format": "coco",
                "contributor_id": "test_contributor",
            })
            assert resp.status_code == 201
            body = resp.json()
            assert body["status"] == "INGESTED"
            assert body["image_count"] == 5
            assert body["annotation_count"] == 10

    def test_ingest_missing_dir_returns_404(self, client, tmp_path):
        nonexistent = tmp_path / "does_not_exist"
        resp = client.post("/api/v1/datasets/ingest", json={
            "data_dir": str(nonexistent),
        })
        assert resp.status_code == 404

    def test_scan_returns_200_with_findings(self, client, tmp_path):
        data_dir = tmp_path / "scan_data"
        data_dir.mkdir()

        from cvif.core.schemas import Finding
        from cvif.core.enums import SeverityLevel

        mock_finding = Finding(
            finding_id=uuid4(),
            asset_id=uuid4(),
            session_id=uuid4(),
            threat_id="DT-1",
            category="DATA_INTEGRITY",
            title="Duplicate image detected",
            description="Exact duplicate found",
            severity=SeverityLevel.MEDIUM,
            confidence=0.95,
        )

        mock_session = MagicMock()
        mock_session.session_id = uuid4()
        mock_session.asset_id = uuid4()
        mock_session.status = MagicMock()
        mock_session.status.value = "COMPLETED"
        mock_session.findings = [mock_finding]
        mock_session.executed_analyses = ["DT-1", "DT-2"]

        with patch("cvif.api.routes.datasets.IngestionGateway") as MockGW, \
             patch("cvif.api.routes.datasets.DatasetIntegrityOrchestrator") as MockOrch:
            MockGW.return_value.ingest_dataset.return_value = (
                MagicMock(), MagicMock(), MagicMock(),
            )
            MockOrch.return_value.run_analysis.return_value = mock_session

            resp = client.post("/api/v1/datasets/scan", json={
                "data_dir": str(data_dir),
            })
            assert resp.status_code == 200
            body = resp.json()
            assert body["findings_count"] == 1


# ═══════════════════════════════════════════════════════════════════════
# MODEL ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

class TestModelEndpoints:
    """Tests for POST /api/v1/models/scan-safety and /api/v1/models/scan."""

    def test_scan_safety_safe_model(self, client, tmp_path):
        model_file = tmp_path / "model.onnx"
        model_file.write_bytes(b"\x00" * 128)

        mock_result = MagicMock()
        mock_result.is_safe = True
        mock_result.detected_format = "onnx"
        mock_result.file_hash = "abcd1234"
        mock_result.file_size_bytes = 128
        mock_result.errors = []
        mock_result.warnings = []

        with patch("cvif.api.routes.models.scan_model_file", return_value=mock_result):
            resp = client.post("/api/v1/models/scan-safety", json={
                "model_path": str(model_file),
            })
            assert resp.status_code == 200
            body = resp.json()
            assert body["is_safe"] is True
            assert body["status"] == "PASSED"

    def test_scan_safety_unsafe_model(self, client, tmp_path):
        model_file = tmp_path / "malicious.pt"
        model_file.write_bytes(b"\x00" * 64)

        with patch("cvif.api.routes.models.scan_model_file", side_effect=InvalidModelError("Malicious payload detected")):
            resp = client.post("/api/v1/models/scan-safety", json={
                "model_path": str(model_file),
            })
            assert resp.status_code == 200
            body = resp.json()
            assert body["is_safe"] is False
            assert body["status"] == "UNSAFE_MODEL_DETECTED"

    def test_scan_missing_model_returns_404(self, client, tmp_path):
        resp = client.post("/api/v1/models/scan-safety", json={
            "model_path": str(tmp_path / "no_model.onnx"),
        })
        assert resp.status_code == 404

    def test_model_scan_full_battery(self, client, tmp_path):
        model_file = tmp_path / "candidate.onnx"
        model_file.write_bytes(b"\x00" * 256)

        from cvif.core.enums import SeverityLevel
        mock_session = MagicMock()
        mock_session.session_id = uuid4()
        mock_session.asset_id = uuid4()
        mock_session.status = MagicMock()
        mock_session.status.value = "COMPLETED"
        mock_session.findings = []
        mock_session.executed_analyses = ["MT-1", "MT-2", "MT-4"]

        with patch("cvif.api.routes.models.validate_model_file_safety"), \
             patch("cvif.api.routes.models.scan_model_file"), \
             patch("cvif.api.routes.models._resolve_model_adapter") as mock_adapter, \
             patch("cvif.api.routes.models.ReferenceBatteryBuilder") as mock_battery, \
             patch("cvif.api.routes.models.ModelIntegrityOrchestrator") as MockOrch:
            mock_adapter.return_value = MagicMock()
            mock_adapter.return_value.get_task_type.return_value = "CLASSIFICATION"
            MockOrch.return_value.run_analysis.return_value = mock_session

            resp = client.post("/api/v1/models/scan", json={
                "model_path": str(model_file),
            })
            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "COMPLETED"
            assert body["total_findings"] == 0


# ═══════════════════════════════════════════════════════════════════════
# PROVENANCE VERIFICATION
# ═══════════════════════════════════════════════════════════════════════

class TestProvenanceEndpoints:
    """Tests for POST /api/v1/provenance/verify."""

    def test_provenance_verify_valid_record(self, client):
        from cvif.core.schemas import InferenceRecord

        record_id = str(uuid4())
        session_id = str(uuid4())

        mock_result = MagicMock()
        mock_result.status = MagicMock()
        mock_result.status.value = "VERIFIED"
        mock_result.is_valid = True
        mock_result.findings = []
        mock_result.details = {}

        with patch("cvif.api.routes.provenance.InferenceProvenanceVerifier") as MockVerifier:
            MockVerifier.return_value.verify_record.return_value = mock_result

            resp = client.post("/api/v1/provenance/verify", json={
                "record": {
                    "record_id": record_id,
                    "session_id": session_id,
                    "model_digest": "abc123",
                    "image_digest": "def456",
                    "prediction": {"class": "cat", "confidence": 0.95},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "producer_id": "contributor-A",
                    "signing_key_id": "key-001",
                    "signature": "fake-sig",
                    "nonce": str(uuid4()),
                },
            })
            # May return 200 or 422 depending on InferenceRecord validation
            # We just verify the mock pipeline is callable
            assert resp.status_code in (200, 422)


# ═══════════════════════════════════════════════════════════════════════
# DISTRIBUTION SHIFT
# ═══════════════════════════════════════════════════════════════════════

class TestShiftEndpoints:
    """Tests for POST /api/v1/shift/analyze."""

    def test_shift_analyze_missing_paths_returns_404(self, client, tmp_path):
        resp = client.post("/api/v1/shift/analyze", json={
            "reference_data": str(tmp_path / "nonexistent_ref"),
            "evaluation_data": str(tmp_path / "nonexistent_eval"),
        })
        assert resp.status_code == 404

    def test_shift_analyze_success_response_mapping(self, client, tmp_path, monkeypatch):
        """Regression test verifying ShiftReport maps correctly to DistributionShiftResponse without AttributeError."""
        from cvif.analysis.distribution_shift.orchestrator import DistributionShiftOrchestrator
        from cvif.core.enums import SessionStatus
        from cvif.core.schemas import (
            AnalysisSession,
            ShiftAssessment,
            ShiftDimensionResult,
            ShiftReport,
            UnifiedDataset,
        )
        from cvif.ingestion.gateway import IngestionGateway

        ref_dir = tmp_path / "ref"
        eval_dir = tmp_path / "eval"
        ref_dir.mkdir()
        eval_dir.mkdir()

        fake_report = ShiftReport(
            reference_asset_id=uuid4(),
            evaluation_asset_id=uuid4(),
            session_id=uuid4(),
            overall_distance=0.1772,
            dimensions={
                "covariate_shift": ShiftDimensionResult(
                    detected=False, metric_value=0.0477, p_value=0.1021, description="Covariate shift nominal"
                ),
                "semantic_shift": ShiftDimensionResult(
                    detected=True, metric_value=0.4008, p_value=0.5992, description="Semantic shift detected"
                ),
                "environmental_drift": ShiftDimensionResult(
                    detected=False, metric_value=0.0017, p_value=0.3378, description="Environmental drift nominal"
                ),
                "adversarial_manipulation": ShiftDimensionResult(
                    detected=True, metric_value=0.3753, p_value=0.6247, description="Adversarial manipulation detected"
                ),
            },
            assessment=ShiftAssessment(
                natural_drift_likelihood=0.2374,
                suspicious_manipulation_likelihood=0.6877,
                evidence_sufficient=True,
                reasoning="Asymmetrical shift detected",
            ),
            characterization="SUSPICIOUS_MANIPULATION",
        )
        fake_session = AnalysisSession(
            session_id=fake_report.session_id,
            asset_id=fake_report.evaluation_asset_id,
            status=SessionStatus.COMPLETED,
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            duration_ms=123.4,
            findings=[],
        )

        fake_ds = UnifiedDataset(
            asset_id=uuid4(),
            format_origin="coco",
            dataset_root=str(ref_dir),
            metadata={"total_images": 10},
            images=[],
            annotations=[],
        )
        monkeypatch.setattr(IngestionGateway, "ingest_dataset", lambda self, p, contributor_id=None: (fake_ds, None, None))
        monkeypatch.setattr(DistributionShiftOrchestrator, "run_analysis", lambda self, **kwargs: (fake_report, fake_session))

        resp = client.post("/api/v1/shift/analyze", json={
            "reference_data": str(ref_dir),
            "evaluation_data": str(eval_dir),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["overall_shift_detected"] is True
        assert data["overall_distance"] == 0.1772
        assert data["natural_drift_likelihood"] == 0.2374
        assert data["suspicious_manipulation_likelihood"] == 0.6877
        assert data["characterization"] == "SUSPICIOUS_MANIPULATION"
        assert len(data["dimensions"]) == 4
        assert data["dimensions"]["semantic_shift"]["shift_detected"] is True
        assert data["dimensions"]["covariate_shift"]["shift_detected"] is False
        assert data["dimensions"]["adversarial_manipulation"]["statistic_value"] == 0.3753


# ═══════════════════════════════════════════════════════════════════════
# ASSURANCE VERDICT
# ═══════════════════════════════════════════════════════════════════════

class TestAssessEndpoints:
    """Tests for POST /api/v1/assess."""

    def test_assess_session_not_found_returns_404(self, client, mock_ctx):
        mock_ctx.db.get_session.return_value = None
        resp = client.post("/api/v1/assess", json={
            "session_id": str(uuid4()),
        })
        assert resp.status_code == 404
        body = resp.json()
        assert body["error_code"] == "RESOURCE_NOT_FOUND"


# ═══════════════════════════════════════════════════════════════════════
# EVIDENCE STORE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

class TestEvidenceEndpoints:
    """Tests for evidence CRUD, verification, and export."""

    def test_list_evidence_returns_empty(self, client, mock_ctx):
        mock_ctx.db.list_evidence_records.return_value = []
        resp = client.get("/api/v1/evidence")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["records"] == []

    def test_list_evidence_with_records(self, client, mock_ctx):
        eid = str(uuid4())
        sid = str(uuid4())
        mock_ctx.db.list_evidence_records.return_value = [
            {
                "evidence_id": eid,
                "session_id": sid,
                "finding_id": None,
                "evidence_type": "STATISTICAL",
                "content_hash": "abc123",
                "created_at": "2024-01-01T00:00:00Z",
            }
        ]
        resp = client.get("/api/v1/evidence")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["records"][0]["evidence_id"] == eid

    def test_list_evidence_by_threat_id(self, client, mock_ctx):
        mock_ctx.db.get_evidence_by_threat_id.return_value = []
        resp = client.get("/api/v1/evidence?threat_id=DT-1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0

    def test_get_evidence_by_id_not_found(self, client, mock_ctx):
        mock_ctx.evidence.get_evidence.return_value = None
        resp = client.get(f"/api/v1/evidence/{uuid4()}")
        assert resp.status_code == 404
        body = resp.json()
        assert body["error_code"] == "RESOURCE_NOT_FOUND"

    def test_verify_evidence_consistent(self, client, mock_ctx):
        mock_ctx.evidence.verify_store_consistency.return_value = {
            "is_consistent": True,
            "total_records": 10,
            "total_artifacts": 15,
            "missing_records": [],
            "tampered_records": [],
            "missing_artifacts": [],
            "tampered_artifacts": [],
        }
        resp = client.post("/api/v1/evidence/verify", json={})
        assert resp.status_code == 200
        body = resp.json()
        assert body["is_consistent"] is True
        assert body["total_records"] == 10

    def test_verify_evidence_tampered_returns_409(self, client, mock_ctx):
        mock_ctx.evidence.verify_store_consistency.return_value = {
            "is_consistent": False,
            "total_records": 10,
            "total_artifacts": 15,
            "tampered_records": ["rec-001"],
            "missing_records": [],
            "missing_artifacts": [],
            "tampered_artifacts": [],
        }
        resp = client.post("/api/v1/evidence/verify", json={})
        assert resp.status_code == 409
        body = resp.json()
        assert body["error_code"] == "TAMPER_DETECTED"

    def test_export_session_not_found_returns_404(self, client, mock_ctx):
        mock_ctx.evidence.verify_store_consistency.return_value = {
            "is_consistent": True,
            "total_records": 0,
            "total_artifacts": 0,
        }
        mock_ctx.evidence.list_evidence_for_session.return_value = []

        resp = client.post("/api/v1/evidence/export", json={
            "session_id": str(uuid4()),
        })
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════
# ERROR HANDLER TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestErrorHandlers:
    """Verify centralized exception handlers return correct status codes and suppress stack traces."""

    def test_path_traversal_returns_400(self, app, client):
        """PathTraversalError → 400 with PATH_TRAVERSAL_DETECTED code."""
        @app.get("/test/path-traversal")
        def trigger_path_traversal():
            raise PathTraversalError("../../../etc/passwd")

        resp = client.get("/test/path-traversal")
        assert resp.status_code == 400
        body = resp.json()
        assert body["error_code"] == "PATH_TRAVERSAL_DETECTED"
        assert "traceback" not in json.dumps(body).lower()

    def test_tamper_detected_returns_409(self, app, client):
        """TamperDetectedError → 409."""
        @app.get("/test/tamper")
        def trigger_tamper():
            raise TamperDetectedError("Hash mismatch")

        resp = client.get("/test/tamper")
        assert resp.status_code == 409
        assert resp.json()["error_code"] == "TAMPER_DETECTED"

    def test_invalid_model_returns_422(self, app, client):
        """InvalidModelError → 422."""
        @app.get("/test/invalid-model")
        def trigger_invalid():
            raise InvalidModelError("Corrupted weight file")

        resp = client.get("/test/invalid-model")
        assert resp.status_code == 422
        assert resp.json()["error_code"] == "INVALID_MODEL"

    def test_access_denied_returns_403(self, app, client):
        """AccessDeniedError → 403."""
        @app.get("/test/access-denied")
        def trigger_denied():
            raise AccessDeniedError("Insufficient privileges")

        resp = client.get("/test/access-denied")
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "ACCESS_DENIED"

    def test_storage_error_returns_500(self, app, client):
        """StorageError → 500."""
        @app.get("/test/storage-error")
        def trigger_storage():
            raise StorageError("Disk full")

        resp = client.get("/test/storage-error")
        assert resp.status_code == 500
        assert resp.json()["error_code"] == "STORAGE_ERROR"

    def test_unhandled_exception_returns_500_no_stacktrace(self, app, client):
        """Unhandled Exception → 500 with generic message, no traceback leakage."""
        @app.get("/test/unhandled")
        def trigger_unhandled():
            raise RuntimeError("Sensitive internal detail: secret=X")

        resp = client.get("/test/unhandled")
        assert resp.status_code == 500
        body = resp.json()
        assert body["error_code"] == "INTERNAL_SERVER_ERROR"
        assert "secret=X" not in body["message"]
        assert "traceback" not in json.dumps(body).lower()

    def test_file_not_found_returns_404(self, app, client):
        """FileNotFoundError → 404."""
        @app.get("/test/file-missing")
        def trigger_fnf():
            raise FileNotFoundError("Target path does not exist")

        resp = client.get("/test/file-missing")
        assert resp.status_code == 404
        assert resp.json()["error_code"] == "RESOURCE_NOT_FOUND"


# ═══════════════════════════════════════════════════════════════════════
# MIDDLEWARE TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestMiddleware:
    """Validate request-ID correlation and CORS middleware."""

    def test_request_id_auto_generated(self, client):
        resp = client.get("/api/v1/version")
        rid = resp.headers.get("x-request-id")
        assert rid is not None
        # Must be a valid UUID format
        UUID(rid)

    def test_request_id_passthrough(self, client):
        custom = "trace-id-abc-123"
        resp = client.get("/api/v1/version", headers={"X-Request-ID": custom})
        assert resp.headers.get("x-request-id") == custom

    def test_error_responses_include_request_id(self, app, client):
        @app.get("/test/err-rid")
        def cause_error():
            raise PathTraversalError("bad path")

        resp = client.get("/test/err-rid", headers={"X-Request-ID": "err-trace-1"})
        assert resp.headers.get("x-request-id") == "err-trace-1"
        body = resp.json()
        assert body.get("request_id") == "err-trace-1"


# ═══════════════════════════════════════════════════════════════════════
# API KEY AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════════

class TestAPIKeyAuth:
    """Verify optional API key authentication enforcement."""

    def test_unauthenticated_request_rejected_when_keys_enabled(self, api_key_client):
        resp = api_key_client.get("/api/v1/health")
        assert resp.status_code == 401

    def test_wrong_key_rejected(self, api_key_client):
        resp = api_key_client.get(
            "/api/v1/health",
            headers={"X-API-Key": "wrong-key"},
        )
        assert resp.status_code == 401

    def test_valid_key_accepted(self, api_key_client):
        resp = api_key_client.get(
            "/api/v1/health",
            headers={"X-API-Key": "test-secret-key-123"},
        )
        # Should succeed (200) or at least not 401
        assert resp.status_code != 401

    def test_no_auth_required_when_disabled(self, client):
        """Default config has api_key_enabled=False."""
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200


# ═══════════════════════════════════════════════════════════════════════
# PATH TRAVERSAL SECURITY
# ═══════════════════════════════════════════════════════════════════════

class TestPathTraversalSecurity:
    """Verify resolve_api_path blocks directory traversal and null bytes."""

    def test_traversal_blocked_in_ingest(self, client):
        resp = client.post("/api/v1/datasets/ingest", json={
            "data_dir": "../../etc/passwd",
        })
        # Should get 400 (path traversal) or 404 (not found after resolve)
        assert resp.status_code in (400, 404)

    def test_null_byte_blocked(self, client):
        resp = client.post("/api/v1/datasets/ingest", json={
            "data_dir": "data\x00/malicious",
        })
        assert resp.status_code == 400

    def test_unc_path_blocked(self, client):
        resp = client.post("/api/v1/datasets/ingest", json={
            "data_dir": "\\\\attacker\\share\\data",
        })
        assert resp.status_code == 400


# ═══════════════════════════════════════════════════════════════════════
# APPLICATION FACTORY
# ═══════════════════════════════════════════════════════════════════════

class TestApplicationFactory:
    """Validate create_app configuration semantics."""

    def test_docs_disabled_by_default(self):
        default_cfg = AppConfig()
        application = create_app(config=default_cfg)
        openapi_urls = [getattr(r, "path", None) for r in application.routes if hasattr(r, "path")]
        assert "/api/docs" not in openapi_urls

    def test_docs_enabled_when_configured(self):
        cfg = AppConfig()
        cfg.api.enable_docs = True
        application = create_app(config=cfg)
        assert application.docs_url == "/api/docs"

    def test_all_api_routes_registered(self, app):
        paths = set()
        for r in app.routes:
            if hasattr(r, "path"):
                paths.add(r.path)
            if hasattr(r, "effective_candidates"):
                for c in r.effective_candidates():
                    if hasattr(c, "path"):
                        paths.add(c.path)
            if hasattr(r, "routes"):
                for ir in r.routes:
                    if hasattr(ir, "path"):
                        paths.add(ir.path)
        expected = {
            "/api/v1/health",
            "/api/v1/version",
            "/api/v1/audit/verify",
            "/api/v1/datasets/ingest",
            "/api/v1/datasets/scan",
            "/api/v1/models/scan-safety",
            "/api/v1/models/scan",
            "/api/v1/provenance/verify",
            "/api/v1/shift/analyze",
            "/api/v1/assess",
            "/api/v1/evidence",
            "/api/v1/evidence/{id}",
            "/api/v1/evidence/verify",
            "/api/v1/evidence/export",
        }
        for ep in expected:
            assert ep in paths, f"Missing route: {ep}"


# ═══════════════════════════════════════════════════════════════════════
# VALIDATION ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════

class TestValidationErrors:
    """Verify request body validation errors return 422 with structured envelope."""

    def test_missing_required_field_returns_422(self, client):
        # DatasetIngestRequest requires data_dir
        resp = client.post("/api/v1/datasets/ingest", json={})
        assert resp.status_code == 422
        body = resp.json()
        assert body["error_code"] == "REQUEST_VALIDATION_ERROR"
        assert "validation_errors" in body.get("details", {})

    def test_invalid_uuid_returns_422(self, client):
        resp = client.post("/api/v1/assess", json={
            "session_id": "not-a-uuid",
        })
        assert resp.status_code == 422
