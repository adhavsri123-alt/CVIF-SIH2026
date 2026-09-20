"""Phase 12 — Final Hardening & Polish Test Suite.

Authoritative verification for Phase 12 hardening items:
- F-12-1: PayloadSizeLimitMiddleware (Content-Length check, streaming cutoff, HTTP 413, Request-ID)
- F-12-2: Starlette HTTP 422 deprecation cleanup and error envelope verification
- F-12-3: Subprocess environment isolation (_build_isolated_env, PYTHONPATH enforcement, env filtering)
- F-12-4: Bidirectional Evidence Store consistency (disk-to-DB orphan evidence and artifact detection)
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from cvif.api.main import PayloadSizeLimitMiddleware, _PayloadTooLargeError, create_app
from cvif.api.schemas import EvidenceConsistencyResponse
from cvif.audit.logger import AuditLogger
from cvif.cli.commands.common import RuntimeContext
from cvif.core.config import APIConfig, AppConfig
from cvif.core.enums import EvidenceType
from cvif.core.schemas import ArtifactReference, EvidenceRecord
from cvif.evidence.store import EvidenceStore
from cvif.model.safety import _build_isolated_env
from cvif.storage.database import DatabaseManager


# ============================================================================
# F-12-1: PayloadSizeLimitMiddleware Tests
# ============================================================================

def _create_dummy_app_with_payload_limit(max_bytes: int = 1024) -> FastAPI:
    """Create a minimal ASGI application wrapped with PayloadSizeLimitMiddleware."""
    test_app = FastAPI()

    @test_app.post("/test-upload")
    async def upload_endpoint(request: Request):
        body = await request.body()
        return {"received_bytes": len(body), "status": "OK"}

    test_app.add_middleware(PayloadSizeLimitMiddleware, max_bytes=max_bytes)
    return test_app


def test_payload_size_limit_content_length_fast_path():
    """Verify requests with Content-Length exceeding limit are rejected with HTTP 413 immediately."""
    limit = 100
    app = _create_dummy_app_with_payload_limit(max_bytes=limit)
    client = TestClient(app)

    # Oversized payload
    payload = b"x" * (limit + 50)
    response = client.post(
        "/test-upload",
        content=payload,
        headers={"Content-Type": "application/octet-stream", "X-Request-ID": "test-req-123"},
    )

    assert response.status_code == 413
    data = response.json()
    assert data["status"] == "ERROR"
    assert data["error_code"] == "RESOURCE_EXHAUSTED"
    assert "Request payload exceeds maximum allowable limit" in data["message"]
    assert data["request_id"] == "test-req-123"
    assert response.headers.get("x-request-id") == "test-req-123"


def test_payload_size_limit_allowed_under_limit():
    """Verify requests under the payload limit pass through normally."""
    limit = 1024
    app = _create_dummy_app_with_payload_limit(max_bytes=limit)
    client = TestClient(app)

    payload = b"a" * 50
    response = client.post(
        "/test-upload",
        content=payload,
        headers={"Content-Type": "application/octet-stream"},
    )

    assert response.status_code == 200
    assert response.json() == {"received_bytes": 50, "status": "OK"}


def test_payload_size_limit_streaming_cutoff():
    """Verify streaming/chunked body exceeding limit raises cutoff and sends HTTP 413."""
    import asyncio

    sent_messages = []

    async def _async_test():
        limit = 50
        middleware = PayloadSizeLimitMiddleware(app=None, max_bytes=limit)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/stream",
            "headers": [(b"x-request-id", b"stream-req-456")],
        }

        # Simulate chunked stream sending chunks of 30 bytes
        chunks = [b"a" * 30, b"b" * 30]
        chunk_index = 0

        async def mock_receive():
            nonlocal chunk_index
            if chunk_index < len(chunks):
                chunk = chunks[chunk_index]
                chunk_index += 1
                return {"type": "http.request", "body": chunk, "more_body": True}
            return {"type": "http.request", "body": b"", "more_body": False}

        async def mock_send(msg):
            sent_messages.append(msg)

        async def mock_inner_app(sc, rec, snd):
            while True:
                m = await rec()
                if not m.get("more_body", False):
                    break

        middleware.app = mock_inner_app
        await middleware(scope, mock_receive, mock_send)

        # Verify HTTP 413 response start and body were emitted
        assert len(sent_messages) == 2

    asyncio.run(_async_test())
    assert sent_messages[0]["type"] == "http.response.start"
    assert sent_messages[0]["status"] == 413
    assert sent_messages[1]["type"] == "http.response.body"
    body_data = json.loads(sent_messages[1]["body"].decode("utf-8"))
    assert body_data["error_code"] == "RESOURCE_EXHAUSTED"
    assert body_data["request_id"] == "stream-req-456"


def test_payload_size_limit_disabled_when_zero_or_negative():
    """Verify limit check is bypassed when max_bytes <= 0."""
    app = _create_dummy_app_with_payload_limit(max_bytes=0)
    client = TestClient(app)

    payload = b"z" * 2000
    response = client.post(
        "/test-upload",
        content=payload,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 200
    assert response.json()["received_bytes"] == 2000


# ============================================================================
# F-12-3: Subprocess Environment Isolation Tests
# ============================================================================

def test_build_isolated_env_pythonpath_and_allowlist():
    """Verify _build_isolated_env provides valid PYTHONPATH and filters untrusted env vars."""
    fake_key = "_CVIF_UNTRUSTED_TEST_SECRET_KEY"
    os.environ[fake_key] = "secret_attack_payload"

    try:
        env = _build_isolated_env()

        # 1. PYTHONPATH must be set and point to project src/ directory
        assert "PYTHONPATH" in env
        pythonpath = Path(env["PYTHONPATH"])
        assert pythonpath.is_dir()
        assert (pythonpath / "cvif").is_dir()

        # 2. Untrusted variables must NOT leak into subprocess environment
        assert fake_key not in env

        # 3. Essential system variables must be preserved if in os.environ
        for var in ["PATH", "SystemRoot", "TEMP", "HOME"]:
            if var in os.environ:
                assert var in env
                assert env[var] == os.environ[var]
    finally:
        os.environ.pop(fake_key, None)


# ============================================================================
# F-12-4: Bidirectional Evidence Store Consistency Tests
# ============================================================================

@pytest.fixture
def store_env(temp_dir: Path):
    """Provide fully configured EvidenceStore with dedicated DatabaseManager and AuditLogger."""
    db_path = temp_dir / "test_metadata.db"
    audit_path = temp_dir / "test_audit.jsonl"
    ev_dir = temp_dir / "evidence_store"

    db = DatabaseManager(db_path)
    audit = AuditLogger(audit_path)
    store = EvidenceStore(
        base_dir=ev_dir,
        db_manager=db,
        audit_logger=audit,
        enforce_content=True,
    )
    yield store, db, audit
    store.close()
    db.close()


def _make_record(session_id, finding_id=None):
    return EvidenceRecord(
        evidence_id=uuid4(),
        finding_id=finding_id or uuid4(),
        session_id=session_id,
        evidence_type=EvidenceType.STATISTICAL,
        metrics={"score": 0.88},
        narrative="Test evidence record for consistency verification",
        methodology="Statistical verification test",
        reproducibility_info={"seed": 42},
    )


def test_bidirectional_consistency_clean(store_env):
    """Verify consistent store reports is_consistent=True with zero orphans."""
    store, _, _ = store_env
    sess_id = uuid4()
    rec = _make_record(sess_id)

    # Save artifact first
    art_ref = store.save_artifact(
        session_id=sess_id,
        rel_path="weights/digest.bin",
        data=b"sample_artifact_content_123",
        media_type="application/octet-stream",
        description="Weight digest artifact",
    )
    rec.artifacts = [art_ref]

    # Save record
    store.save_evidence(rec)

    audit_res = store.verify_store_consistency(session_id=sess_id)
    assert audit_res["is_consistent"] is True
    assert audit_res["total_records"] == 1
    assert audit_res["total_artifacts"] == 1
    assert audit_res["missing_records"] == []
    assert audit_res["tampered_records"] == []
    assert audit_res["missing_artifacts"] == []
    assert audit_res["tampered_artifacts"] == []
    assert audit_res["orphan_evidence"] == []
    assert audit_res["orphan_artifacts"] == []


def test_bidirectional_consistency_detects_orphan_evidence(store_env):
    """Verify untracked .json files in evidence directory are detected as orphans."""
    store, _, _ = store_env
    sess_id = uuid4()
    rec = _make_record(sess_id)
    store.save_evidence(rec)

    # Create an untracked (orphan) evidence file on disk
    sess_dir = store._get_session_dir(sess_id)
    orphan_file = sess_dir / "evidence" / f"{uuid4()}.json"
    orphan_file.write_text('{"untracked": true}', encoding="utf-8")

    audit_res = store.verify_store_consistency(session_id=sess_id)
    assert audit_res["is_consistent"] is False
    assert len(audit_res["orphan_evidence"]) == 1
    assert orphan_file.name in audit_res["orphan_evidence"][0]


def test_bidirectional_consistency_detects_orphan_artifacts(store_env):
    """Verify untracked files in artifacts directory are detected as orphans."""
    store, _, _ = store_env
    sess_id = uuid4()
    rec = _make_record(sess_id)
    store.save_evidence(rec)

    # Create an untracked (orphan) artifact on disk
    sess_dir = store._get_session_dir(sess_id)
    orphan_art_dir = sess_dir / "artifacts" / "untracked_sub"
    orphan_art_dir.mkdir(parents=True, exist_ok=True)
    orphan_file = orphan_art_dir / "rogue_dump.bin"
    orphan_file.write_bytes(b"rogue data not recorded in db")

    audit_res = store.verify_store_consistency(session_id=sess_id)
    assert audit_res["is_consistent"] is False
    assert len(audit_res["orphan_artifacts"]) == 1
    assert "rogue_dump.bin" in audit_res["orphan_artifacts"][0]


def test_bidirectional_consistency_ignores_temp_atomic_files(store_env):
    """Verify atomic-write temporary files (.tmp_*) are ignored during orphan scan."""
    store, _, _ = store_env
    sess_id = uuid4()
    rec = _make_record(sess_id)
    store.save_evidence(rec)

    sess_dir = store._get_session_dir(sess_id)
    tmp_ev = sess_dir / "evidence" / ".tmp_in_progress.json"
    tmp_ev.write_text('{"partial": true}', encoding="utf-8")

    art_dir = sess_dir / "artifacts"
    art_dir.mkdir(parents=True, exist_ok=True)
    tmp_art = art_dir / ".tmp_art.bin"
    tmp_art.write_bytes(b"partial artifact")

    audit_res = store.verify_store_consistency(session_id=sess_id)
    assert audit_res["is_consistent"] is True
    assert audit_res["orphan_evidence"] == []
    assert audit_res["orphan_artifacts"] == []


# ============================================================================
# F-12-2 & API Integration: Error Handling and Consistency Endpoint
# ============================================================================

def test_api_evidence_consistency_endpoint_surfaces_orphans(tmp_path: Path):
    """Verify /api/v1/evidence/verify route returns orphan fields conforming to schema."""
    cfg = AppConfig().resolve_paths(tmp_path)
    cfg.api.api_key_enabled = False
    cfg.storage.catalog_db_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.evidence.evidence_dir.mkdir(parents=True, exist_ok=True)
    cfg.keystore.keystore_dir.mkdir(parents=True, exist_ok=True)
    cfg.audit.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    ctx = MagicMock(spec=RuntimeContext)
    ctx.config = cfg
    ctx.evidence = MagicMock()
    ctx.evidence.verify_store_consistency.return_value = {
        "total_records": 5,
        "total_artifacts": 2,
        "is_consistent": True,
        "missing_records": [],
        "tampered_records": [],
        "missing_artifacts": [],
        "tampered_artifacts": [],
        "orphan_evidence": [],
        "orphan_artifacts": [],
    }

    app = create_app(config=cfg)
    app.state.ctx = ctx
    client = TestClient(app)

    response = client.post("/api/v1/evidence/verify", json={})
    assert response.status_code == 200
    data = response.json()

    parsed = EvidenceConsistencyResponse(**data)
    assert parsed.is_consistent is True
    assert parsed.total_records == 5
    assert parsed.total_artifacts == 2
    assert parsed.orphan_evidence == []
    assert parsed.orphan_artifacts == []


def test_api_evidence_consistency_endpoint_tamper_detected(tmp_path: Path):
    """Verify /api/v1/evidence/verify returns 409 TamperDetectedError with details on inconsistency."""
    cfg = AppConfig().resolve_paths(tmp_path)
    cfg.api.api_key_enabled = False
    cfg.storage.catalog_db_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.evidence.evidence_dir.mkdir(parents=True, exist_ok=True)
    cfg.keystore.keystore_dir.mkdir(parents=True, exist_ok=True)
    cfg.audit.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    ctx = MagicMock(spec=RuntimeContext)
    ctx.config = cfg
    ctx.evidence = MagicMock()
    ctx.evidence.verify_store_consistency.return_value = {
        "total_records": 1,
        "total_artifacts": 0,
        "is_consistent": False,
        "missing_records": [],
        "tampered_records": [],
        "missing_artifacts": [],
        "tampered_artifacts": [],
        "orphan_evidence": ["orphan.json"],
        "orphan_artifacts": [],
    }

    app = create_app(config=cfg)
    app.state.ctx = ctx
    client = TestClient(app, raise_server_exceptions=False)

    response = client.post("/api/v1/evidence/verify", json={})
    assert response.status_code == 409
    data = response.json()
    assert data["status"] == "ERROR"
    assert data["error_code"] == "TAMPER_DETECTED"
    assert data["details"]["orphan_evidence"] == ["orphan.json"]

