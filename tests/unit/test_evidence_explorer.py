"""Unit and API regression tests for Evidence Explorer functionality.

Validates:
- session/threat/type filtering individually and combined
- case-insensitivity on threat_id and evidence_type
- partial session ID matching without HTTP 422
- empty result state handling
- evidence detail loading with canonical fields and digests
- invalid evidence ID handling returning 404 RESOURCE_NOT_FOUND
- DatabaseManager direct query logic for threat_id and evidence_type
"""

import json
from pathlib import Path
from unittest.mock import MagicMock
from uuid import UUID, uuid4
import pytest
from fastapi.testclient import TestClient

from cvif.api.main import create_app
from cvif.cli.commands.common import RuntimeContext
from cvif.core.config import AppConfig
from cvif.core.enums import EvidenceType
from cvif.core.schemas import ArtifactReference, EvidenceRecord
from cvif.storage.database import DatabaseManager


@pytest.fixture
def mock_ctx():
    """Build a mock RuntimeContext for API tests."""
    ctx = MagicMock(spec=RuntimeContext)
    cfg = AppConfig()
    cfg.api.api_key_enabled = False
    ctx.config = cfg
    ctx.db = MagicMock()
    ctx.evidence = MagicMock()
    ctx.audit = MagicMock()
    ctx.keystore = MagicMock()
    return ctx


@pytest.fixture
def app(mock_ctx):
    application = create_app(config=mock_ctx.config)
    application.state.ctx = mock_ctx
    return application


@pytest.fixture
def client(app):
    return TestClient(app, raise_server_exceptions=False)


# ═══════════════════════════════════════════════════════════════════════
# API ENDPOINT TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestEvidenceExplorerAPI:
    """Tests for /api/v1/evidence filtering, detail loading, and error handling."""

    def test_list_evidence_session_filter(self, client, mock_ctx):
        sid = str(uuid4())
        eid = str(uuid4())
        mock_ctx.db.list_evidence_records.return_value = [
            {
                "evidence_id": eid,
                "session_id": sid,
                "finding_id": None,
                "evidence_type": "STATISTICAL",
                "content_hash": "a" * 64,
                "created_at": "2026-09-20T12:00:00Z",
                "threat_id": "DT-5",
            }
        ]

        resp = client.get(f"/api/v1/evidence?session_id={sid}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["records"][0]["session_id"] == sid
        assert data["records"][0]["threat_id"] == "DT-5"
        mock_ctx.db.list_evidence_records.assert_called_once_with(
            session_id=sid,
            finding_id=None,
            evidence_type=None,
        )

    def test_list_evidence_partial_session_no_422(self, client, mock_ctx):
        """Typing a partial session prefix must NOT throw HTTP 422."""
        mock_ctx.db.list_evidence_records.return_value = []
        resp = client.get("/api/v1/evidence?session_id=2575")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["records"] == []

    def test_list_evidence_threat_filter_and_reproducibility(self, client, mock_ctx):
        eid = str(uuid4())
        sid = str(uuid4())
        mock_ctx.db.get_evidence_by_threat_id.return_value = [
            {
                "evidence_id": eid,
                "session_id": sid,
                "finding_id": None,
                "evidence_type": "STATISTICAL",
                "content_hash": "b" * 64,
                "created_at": "2026-09-20T12:00:00Z",
                "record_json": json.dumps({"reproducibility_info": {"threat_id": "DT-5"}}),
            }
        ]

        resp = client.get("/api/v1/evidence?threat_id=DT-5")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["records"][0]["threat_id"] == "DT-5"
        mock_ctx.db.get_evidence_by_threat_id.assert_called_once_with("DT-5")

    def test_list_evidence_combined_filters(self, client, mock_ctx):
        sid_match = str(uuid4())
        sid_other = str(uuid4())
        mock_ctx.db.get_evidence_by_threat_id.return_value = [
            {
                "evidence_id": str(uuid4()),
                "session_id": sid_match,
                "finding_id": None,
                "evidence_type": "STATISTICAL",
                "content_hash": "c" * 64,
                "created_at": "2026-09-20T12:00:00Z",
                "threat_id": "DT-1",
            },
            {
                "evidence_id": str(uuid4()),
                "session_id": sid_other,
                "finding_id": None,
                "evidence_type": "STATISTICAL",
                "content_hash": "d" * 64,
                "created_at": "2026-09-20T12:00:00Z",
                "threat_id": "DT-1",
            },
            {
                "evidence_id": str(uuid4()),
                "session_id": sid_match,
                "finding_id": None,
                "evidence_type": "BEHAVIORAL",
                "content_hash": "e" * 64,
                "created_at": "2026-09-20T12:00:00Z",
                "threat_id": "DT-1",
            },
        ]

        # Filter by Threat ID + Session ID + Evidence Type
        resp = client.get(f"/api/v1/evidence?threat_id=DT-1&session_id={sid_match}&evidence_type=STATISTICAL")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["records"][0]["session_id"] == sid_match
        assert data["records"][0]["evidence_type"] == "STATISTICAL"

    def test_list_evidence_empty_result(self, client, mock_ctx):
        mock_ctx.db.list_evidence_records.return_value = []
        resp = client.get("/api/v1/evidence?evidence_type=NONEXISTENT")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["records"] == []

    def test_get_evidence_detail_loading(self, client, mock_ctx):
        eid = uuid4()
        sid = uuid4()
        fid = uuid4()

        record = EvidenceRecord(
            evidence_id=eid,
            finding_id=fid,
            session_id=sid,
            evidence_type=EvidenceType.STATISTICAL,
            narrative="Forensic dispersion analysis detected 1 outlier.",
            methodology="Class-conditional Mahalanobis distance with sigma > 3.0",
            metrics={"max_dispersion_score": 4.056, "ood_candidates_count": 1.0},
            artifacts=[
                ArtifactReference(
                    path="heatmaps/dispersion.png",
                    media_type="image/png",
                    description="Visual attribution heatmap",
                )
            ],
            baseline_comparison={"threshold_sigma": 3.0},
            reproducibility_info={"threat_id": "DT-5"},
        )

        mock_ctx.evidence.get_evidence.return_value = record

        resp = client.get(f"/api/v1/evidence/{eid}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["evidence_id"] == str(eid)
        assert data["narrative"] == "Forensic dispersion analysis detected 1 outlier."
        assert data["methodology"] == "Class-conditional Mahalanobis distance with sigma > 3.0"
        assert data["metrics"]["max_dispersion_score"] == 4.056
        assert len(data["artifacts"]) == 1
        assert data["artifacts"][0]["path"] == "heatmaps/dispersion.png"
        assert data["artifacts"][0]["media_type"] == "image/png"
        assert data["reproducibility_info"]["threat_id"] == "DT-5"

    def test_get_evidence_invalid_id_handling(self, client, mock_ctx):
        """Invalid UUID format must cleanly return 404 RESOURCE_NOT_FOUND."""
        resp = client.get("/api/v1/evidence/not-a-valid-uuid")
        assert resp.status_code == 404
        data = resp.json()
        assert data["error_code"] == "RESOURCE_NOT_FOUND"
        assert "invalid UUID format" in data["message"]


# ═══════════════════════════════════════════════════════════════════════
# DATABASE QUERY TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestEvidenceDatabaseQueries:
    """Direct DatabaseManager tests verifying SQLite queries for threat and type matching."""

    @pytest.fixture
    def test_db(self, tmp_path: Path):
        db_file = tmp_path / "test_catalogue.db"
        db = DatabaseManager(db_file)
        yield db
        db.close()

    def test_database_threat_id_matching_reproducibility(self, test_db):
        sid = uuid4()
        eid_dt5 = uuid4()
        eid_mt1 = uuid4()

        rec_dt5 = EvidenceRecord(
            evidence_id=eid_dt5,
            finding_id=uuid4(),
            session_id=sid,
            evidence_type=EvidenceType.STATISTICAL,
            narrative="DT-5 OOD outlier detected",
            methodology="Dispersion test",
            reproducibility_info={"threat_id": "DT-5"},
        )

        rec_mt1 = EvidenceRecord(
            evidence_id=eid_mt1,
            finding_id=uuid4(),
            session_id=sid,
            evidence_type=EvidenceType.BEHAVIORAL,
            narrative="MT-1 AST Safety scan",
            methodology="Static scan",
            reproducibility_info={"threat_id": "MT-1"},
        )

        test_db.save_evidence_record(
            evidence_id=eid_dt5,
            session_id=sid,
            finding_id=rec_dt5.finding_id,
            evidence_type=rec_dt5.evidence_type.value,
            content_hash="hash_dt5",
            file_path="/tmp/dt5.json",
            schema_version="1.0",
            record_json=rec_dt5.model_dump_json(),
        )

        test_db.save_evidence_record(
            evidence_id=eid_mt1,
            session_id=sid,
            finding_id=rec_mt1.finding_id,
            evidence_type=rec_mt1.evidence_type.value,
            content_hash="hash_mt1",
            file_path="/tmp/mt1.json",
            schema_version="1.0",
            record_json=rec_mt1.model_dump_json(),
        )

        # 1. Exact uppercase match
        rows = test_db.get_evidence_by_threat_id("DT-5")
        assert len(rows) == 1
        assert rows[0]["evidence_id"] == str(eid_dt5)

        # 2. Case-insensitive lowercase match
        rows = test_db.get_evidence_by_threat_id("dt-5")
        assert len(rows) == 1
        assert rows[0]["evidence_id"] == str(eid_dt5)

        # 3. Threat prefix match (e.g. "DT")
        rows = test_db.get_evidence_by_threat_id("DT")
        assert len(rows) == 1
        assert rows[0]["evidence_id"] == str(eid_dt5)

        # 4. list_evidence_records with threat_id parameter
        rows = test_db.list_evidence_records(threat_id="MT-1")
        assert len(rows) == 1
        assert rows[0]["evidence_id"] == str(eid_mt1)

        # 5. list_evidence_records with case-insensitive evidence_type
        rows = test_db.list_evidence_records(evidence_type="statistical")
        assert len(rows) == 1
        assert rows[0]["evidence_id"] == str(eid_dt5)

        # 6. list_evidence_records with partial session_id prefix
        prefix = str(sid)[:8]
        rows = test_db.list_evidence_records(session_id=prefix)
        assert len(rows) == 2
