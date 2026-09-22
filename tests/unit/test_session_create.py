"""Regression tests for Create New Session feature.

Verifies:
1. POST /api/v1/sessions/create generates a fully persisted, empty session.
2. The session starts with status INITIALIZING, empty findings, empty analyses, and no verdict.
3. The foreign key constraint on asset_id is properly satisfied by the placeholder asset.
4. Lineage query against the new session reports all stages as NOT RUN and overall status INCOMPLETE / NOT VERIFIED.
5. Subsequent stage results can accumulate into the newly created session.
6. Creating multiple sessions yields distinct, isolated sessions without affecting historical ones.
"""

from pathlib import Path
from uuid import UUID, uuid4
import pytest
from fastapi.testclient import TestClient

from cvif.api.main import create_app
from cvif.audit.logger import AuditLogger
from cvif.cli.commands.common import RuntimeContext
from cvif.core.config import AppConfig
from cvif.core.enums import SeverityLevel, SessionStatus
from cvif.core.schemas import Finding
from cvif.crypto.keystore import KeyStore
from cvif.evidence.store import EvidenceStore
from cvif.provenance.demo import get_demo_keypair
from cvif.storage.database import DatabaseManager


@pytest.fixture
def session_test_env(tmp_path: Path):
    """Set up isolated DB, truststore, and audit log for session testing."""
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
        "ctx": ctx,
    }


def test_create_new_session_empty(session_test_env):
    """Test 1: POST /sessions/create generates a valid, persisted, empty session."""
    client = session_test_env["client"]
    db: DatabaseManager = session_test_env["db"]

    response = client.post("/api/v1/sessions/create", json={"operator_id": "demo_operator"})
    assert response.status_code == 200, response.text
    data = response.json()

    assert "session_id" in data
    assert data["status"] == SessionStatus.INITIALIZING.value
    assert "created_at" in data

    session_id = UUID(data["session_id"])

    # Verify session is persisted in catalogue DB
    db_session = db.get_session(session_id)
    assert db_session is not None
    assert db_session.session_id == session_id
    assert db_session.status == SessionStatus.INITIALIZING
    assert db_session.operator_id == "demo_operator"
    assert db_session.findings == []
    assert db_session.executed_analyses == []
    assert db_session.verdict is None

    # Verify placeholder asset exists and satisfies FK
    db_asset = db.get_asset(db_session.asset_id)
    assert db_asset is not None
    assert db_asset.format == "pending"


def test_new_session_lineage_all_not_run(session_test_env):
    """Test 2: A newly created session starts with all lineage stages as NOT RUN."""
    client = session_test_env["client"]

    create_resp = client.post("/api/v1/sessions/create", json={})
    assert create_resp.status_code == 200
    session_id = create_resp.json()["session_id"]

    lineage_resp = client.get(f"/api/v1/lineage/session/{session_id}")
    assert lineage_resp.status_code == 200, lineage_resp.text
    lineage = lineage_resp.json()

    assert lineage["session_id"] == session_id
    assert lineage["overall_status"] == "INCOMPLETE / NOT VERIFIED"

    # All individual stages must be NOT RUN with zero findings
    assert lineage["dataset"]["status"] == "NOT RUN"
    assert lineage["dataset"]["findings_count"] == 0

    assert lineage["model"]["status"] == "NOT RUN"
    assert lineage["model"]["findings_count"] == 0

    assert lineage["inference"]["status"] == "NOT RUN"
    assert lineage["inference"]["is_valid"] is False

    assert lineage["distribution"]["status"] == "NOT RUN"
    assert lineage["distribution"]["executed"] is False

    assert lineage["evidence"]["status"] == "NOT RUN"
    assert lineage["evidence"]["total_records"] == 0

    assert lineage["assurance"]["status"] == "NOT RUN"
    assert lineage["assurance"]["assessed"] is False


def test_session_accumulates_results(session_test_env):
    """Test 3: Subsequent stage executions cleanly accumulate into the newly created session."""
    client = session_test_env["client"]
    db: DatabaseManager = session_test_env["db"]

    create_resp = client.post("/api/v1/sessions/create", json={})
    assert create_resp.status_code == 200
    session_id = UUID(create_resp.json()["session_id"])
    db_sess = db.get_session(session_id)

    # Simulate subsequent stage execution targeting this session
    sample_finding = Finding(
        finding_id=uuid4(),
        asset_id=db_sess.asset_id,
        session_id=session_id,
        threat_id="DT-1",
        category="DATA_INTEGRITY",
        severity=SeverityLevel.LOW,
        confidence=0.9,
        title="Dataset Hash Verified",
        description="Dataset hash verified",
    )

    db.update_session_section(
        session_id=session_id,
        section="dataset",
        status=SessionStatus.COMPLETED,
        executed_analyses=["DT-1"],
        findings=[sample_finding],
    )

    updated = db.get_session(session_id)
    assert updated is not None
    assert len(updated.findings) == 1
    assert updated.findings[0].description == "Dataset hash verified"
    assert "DT-1" in updated.executed_analyses


def test_create_session_does_not_affect_existing(session_test_env):
    """Test 4: Creating multiple sessions generates independent, non-conflicting sessions."""
    client = session_test_env["client"]
    db: DatabaseManager = session_test_env["db"]

    resp1 = client.post("/api/v1/sessions/create", json={"operator_id": "op_1"})
    resp2 = client.post("/api/v1/sessions/create", json={"operator_id": "op_2"})

    sid1 = UUID(resp1.json()["session_id"])
    sid2 = UUID(resp2.json()["session_id"])

    assert sid1 != sid2

    s1 = db.get_session(sid1)
    s2 = db.get_session(sid2)

    assert s1 is not None and s2 is not None
    assert s1.operator_id == "op_1"
    assert s2.operator_id == "op_2"
