"""Unit tests for storage foundation: SafeFileStore and DatabaseManager."""

from pathlib import Path
import pytest
from uuid import uuid4

from cvif.core.enums import AssetStatus, AssetType, Disposition, SeverityLevel
from cvif.core.exceptions import PathTraversalError, StorageError
from cvif.core.schemas import (
    AnalysisSession,
    AssetFileManifestEntry,
    AssetRegistration,
    AssuranceVerdict,
    Finding,
    HashManifest,
)
from cvif.storage.filestore import SafeFileStore
from cvif.storage.database import DatabaseManager


def test_filestore_path_traversal_protection(temp_dir: Path):
    store = SafeFileStore(temp_dir / "store")

    # Safe write and read
    store.write_text("sub/dir/test.txt", "hello safe storage")
    assert store.read_text("sub/dir/test.txt") == "hello safe storage"

    # Attempt path traversal out of store
    with pytest.raises(PathTraversalError):
        store.resolve("../escaped.txt")

    with pytest.raises(PathTraversalError):
        store.write_text("../../etc/passwd", "evil")

    with pytest.raises(PathTraversalError):
        store.read_text("../outside.txt")


def test_filestore_content_addressed_storage(temp_dir: Path):
    store = SafeFileStore(temp_dir / "store")
    data = b"image_tensor_bytes_12345"

    digest, rel_path = store.store_content_addressed(data, extension=".bin")
    assert len(digest) == 64
    assert store.exists(rel_path)
    assert store.read_bytes(rel_path) == data


def test_database_manager_asset_crud(temp_dir: Path):
    db = DatabaseManager(temp_dir / "catalog.db")

    manifest = HashManifest(
        algorithm="sha256",
        entries=[
            AssetFileManifestEntry(path="img1.jpg", digest="a" * 64, size_bytes=100)
        ],
    )
    asset = AssetRegistration(
        asset_id=uuid4(),
        asset_type=AssetType.DATASET,
        format="yolo",
        file_paths=["img1.jpg"],
        hash_manifest=manifest,
        total_size_bytes=100,
        contributor_id="recon_squad_3",
    )

    db.save_asset(asset)
    fetched = db.get_asset(asset.asset_id)
    assert fetched is not None
    assert fetched.asset_id == asset.asset_id
    assert fetched.format == "yolo"
    assert fetched.contributor_id == "recon_squad_3"

    # List
    datasets = db.list_assets(asset_type=AssetType.DATASET)
    assert len(datasets) == 1


def test_database_manager_session_findings_verdict(temp_dir: Path):
    db = DatabaseManager(temp_dir / "sessions.db")

    # Create asset first (foreign key requirement)
    asset = AssetRegistration(
        asset_type=AssetType.MODEL,
        format="onnx",
        hash_manifest=HashManifest(),
        total_size_bytes=5000,
    )
    db.save_asset(asset)

    session = AnalysisSession(
        asset_id=asset.asset_id,
        requested_analyses=["backdoor_search"],
    )
    db.save_session(session)

    # Finding
    finding = Finding(
        asset_id=asset.asset_id,
        session_id=session.session_id,
        threat_id="MT-1",
        category="MODEL_INTEGRITY",
        severity=SeverityLevel.CRITICAL,
        confidence=0.95,
        title="Weights Anomaly",
        description="Suspicious weight distribution in conv5",
    )
    db.save_finding(finding)

    # Verdict
    verdict = AssuranceVerdict(
        asset_id=asset.asset_id,
        session_id=session.session_id,
        composite_risk_score=0.92,
        disposition=Disposition.QUARANTINE,
        summary="Model compromised with backdoor.",
    )
    db.save_verdict(verdict)

    # Verify retrieval
    findings = db.get_findings_for_session(session.session_id)
    assert len(findings) == 1
    assert findings[0].threat_id == "MT-1"

    fetched_verdict = db.get_verdict_for_session(session.session_id)
    assert fetched_verdict is not None
    assert fetched_verdict.disposition == Disposition.QUARANTINE


def test_database_nonce_replay_protection(temp_dir: Path):
    db = DatabaseManager(temp_dir / "replay.db")

    nonce = "unique_nonce_abc123"
    rec_id = str(uuid4())
    ts = "2026-09-18T12:00:00Z"

    # First attempt: success
    assert db.record_nonce_if_new(nonce, rec_id, ts) is True

    # Replay attempt: rejected
    assert db.record_nonce_if_new(nonce, rec_id, ts) is False
