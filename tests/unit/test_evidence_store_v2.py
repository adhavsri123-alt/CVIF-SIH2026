"""Phase 8/12 — Comprehensive Evidence Store Test Matrix (Categories A–T).

Authoritative verification for write-once immutability, relational indexing,
streaming SHA-256 artifact verification, path traversal defenses, air-gap execution,
audit chaining, anti-stub sensitivity, and scale benchmarks.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import time
from typing import List
import pytest
from uuid import uuid4

from cvif.audit.logger import AuditLogger
from cvif.core.enums import AuditEventType, EvidenceType, SeverityLevel, Disposition
from cvif.core.exceptions import (
    CorruptedArtifactError,
    EvidenceImmutableError,
    PathTraversalError,
    SchemaValidationError,
    StorageError,
    TamperDetectedError,
)
from cvif.core.schemas import (
    ArtifactReference,
    AssuranceVerdict,
    EvidenceRecord,
    Finding,
)
from cvif.crypto.hashing import sha256_bytes, sha256_file
from cvif.evidence.store import EvidenceStore
from cvif.storage.database import DatabaseManager


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


def _make_sample_record(session_id=None, finding_id=None, score=0.92):
    return EvidenceRecord(
        evidence_id=uuid4(),
        finding_id=finding_id or uuid4(),
        session_id=session_id or uuid4(),
        evidence_type=EvidenceType.STATISTICAL,
        metrics={"anomaly_score": score, "p_value": 0.002},
        narrative="Outlier detected in feature activation space",
        methodology="Mahalanobis distance on layer pool5",
        reproducibility_info={"seed": 42, "threshold": 0.85},
    )


# =====================================================================
# Category A: Create & Persist EvidenceRecord
# =====================================================================
def test_category_a_create_and_persist(store_env):
    store, db, _ = store_env
    record = _make_sample_record()

    path = store.save_evidence(record)
    assert path.is_file()
    assert path.name == f"{record.evidence_id}.json"

    # Verify database index row exists
    db_row = db.get_evidence_record(record.evidence_id)
    assert db_row is not None
    assert db_row["evidence_id"] == str(record.evidence_id)
    assert db_row["session_id"] == str(record.session_id)
    assert db_row["finding_id"] == str(record.finding_id)
    assert db_row["evidence_type"] == EvidenceType.STATISTICAL.value
    assert db_row["content_hash"] == sha256_bytes(record.to_canonical_bytes())


# =====================================================================
# Category B: Retrieve EvidenceRecord by ID
# =====================================================================
def test_category_b_retrieve_by_id(store_env):
    store, _, _ = store_env
    record = _make_sample_record(score=0.88)
    store.save_evidence(record)

    fetched = store.get_evidence(record.evidence_id, verify_integrity=True)
    assert fetched is not None
    assert fetched.evidence_id == record.evidence_id
    assert fetched.finding_id == record.finding_id
    assert fetched.session_id == record.session_id
    assert fetched.metrics["anomaly_score"] == 0.88
    assert fetched.narrative == record.narrative
    assert fetched.methodology == record.methodology


# =====================================================================
# Category C: Content Hash Verification
# =====================================================================
def test_category_c_content_hash_verification(store_env):
    store, db, _ = store_env
    record = _make_sample_record()
    store.save_evidence(record)

    expected_hash = sha256_bytes(record.to_canonical_bytes())
    db_row = db.get_evidence_record(record.evidence_id)
    assert db_row["content_hash"] == expected_hash

    # Hash lookup
    by_hash = store.get_evidence_by_hash(expected_hash)
    assert by_hash is not None
    assert by_hash.evidence_id == record.evidence_id


# =====================================================================
# Category D: Metadata Tampering Detection
# =====================================================================
def test_category_d_metadata_tampering_detection(store_env):
    store, db, audit = store_env
    record = _make_sample_record()
    store.save_evidence(record)

    # Maliciously edit content_hash in SQLite
    with db.transaction() as cur:
        cur.execute(
            "UPDATE evidence_records SET content_hash = ? WHERE evidence_id = ?;",
            ("0000000000000000000000000000000000000000000000000000000000000000", str(record.evidence_id)),
        )

    # Retrieval must detect tamper and raise TamperDetectedError
    with pytest.raises(TamperDetectedError):
        store.get_evidence(record.evidence_id, verify_integrity=True)


# =====================================================================
# Category E: Disk Content Tampering Detection
# =====================================================================
def test_category_e_disk_content_tampering_detection(store_env):
    store, _, audit = store_env
    record = _make_sample_record()
    target_path = store.save_evidence(record)

    # Modify JSON payload directly on disk
    corrupted_data = json.loads(target_path.read_text(encoding="utf-8"))
    corrupted_data["metrics"]["anomaly_score"] = 0.01  # Alter score
    target_path.write_text(json.dumps(corrupted_data), encoding="utf-8")

    # Retrieval must detect disk modification
    with pytest.raises(TamperDetectedError):
        store.get_evidence(record.evidence_id, verify_integrity=True)


# =====================================================================
# Category F: Duplicate Insertion Rejection
# =====================================================================
def test_category_f_duplicate_insertion_rejected(store_env):
    store, _, _ = store_env
    record = _make_sample_record()
    store.save_evidence(record)

    # Saving the exact same record twice must raise EvidenceImmutableError
    with pytest.raises(EvidenceImmutableError):
        store.save_evidence(record)


# =====================================================================
# Category G: Write-Once Enforcement (Different Content Same ID & Artifacts)
# =====================================================================
def test_category_g_write_once_enforcement(store_env):
    store, _, _ = store_env
    record1 = _make_sample_record()
    store.save_evidence(record1)

    # Create a record with the same evidence_id but different narrative/metrics
    record2 = EvidenceRecord(
        evidence_id=record1.evidence_id,
        finding_id=uuid4(),
        session_id=record1.session_id,
        evidence_type=EvidenceType.STATISTICAL,
        metrics={"anomaly_score": 0.05},
        narrative="Altered benign narrative",
        methodology="Tampered methodology",
    )

    with pytest.raises(EvidenceImmutableError):
        store.save_evidence(record2)

    # Artifact write-once test
    session_id = uuid4()
    art1 = store.save_artifact(
        session_id=session_id,
        rel_path="heatmaps/cam.png",
        data=b"original_png_bytes",
        media_type="image/png",
        description="Original CAM",
    )
    assert art1 is not None

    # Overwriting same rel_path must raise EvidenceImmutableError
    with pytest.raises(EvidenceImmutableError):
        store.save_artifact(
            session_id=session_id,
            rel_path="heatmaps/cam.png",
            data=b"replaced_fake_bytes",
            media_type="image/png",
            description="Replaced CAM",
        )


# =====================================================================
# Category H: Path Traversal Rejection
# =====================================================================
def test_category_h_path_traversal_rejected(store_env):
    store, _, _ = store_env
    session_id = uuid4()

    # Traversal in rel_path
    traversal_paths = [
        "../../etc/passwd",
        "..\\..\\windows\\system32\\calc.exe",
        "sub/../../secret.txt",
        "/absolute/path/file.png",
        "C:\\Windows\\system32\\config.sys",
    ]

    for bad_path in traversal_paths:
        with pytest.raises(PathTraversalError):
            store.save_artifact(
                session_id=session_id,
                rel_path=bad_path,
                data=b"test",
                media_type="text/plain",
                description="traversal attempt",
            )

        with pytest.raises(PathTraversalError):
            store.read_artifact(session_id=session_id, rel_path=bad_path)


# =====================================================================
# Category I: Missing Artifact Detection
# =====================================================================
def test_category_i_missing_artifact_detection(store_env):
    store, _, _ = store_env
    session_id = uuid4()

    art_ref = store.save_artifact(
        session_id=session_id,
        rel_path="reports/diag.json",
        data=b'{"test": 1}',
        media_type="application/json",
        description="Diagnostic report",
    )

    record = EvidenceRecord(
        evidence_id=uuid4(),
        finding_id=uuid4(),
        session_id=session_id,
        evidence_type=EvidenceType.VISUAL,
        artifacts=[art_ref],
        narrative="Record referencing diagnostic artifact",
        methodology="Visual attribution",
    )
    store.save_evidence(record)

    # Delete physical artifact file from disk
    sess_dir = store._get_session_dir(session_id)
    phys_file = sess_dir / art_ref.path
    assert phys_file.is_file()
    phys_file.unlink()

    # Verification on retrieval must fail with CorruptedArtifactError
    with pytest.raises(CorruptedArtifactError):
        store.get_evidence(record.evidence_id, verify_integrity=True)


# =====================================================================
# Category J: Orphan Artifact Detection
# =====================================================================
def test_category_j_orphan_and_consistency_detection(store_env):
    store, _, _ = store_env
    session_id = uuid4()

    art_ref = store.save_artifact(
        session_id=session_id,
        rel_path="metrics/trace.json",
        data=b"{}",
        media_type="application/json",
        description="Trace dump",
    )

    # Initially consistent
    audit_res = store.verify_store_consistency(session_id=session_id)
    assert audit_res["is_consistent"] is True

    # Delete the artifact file
    sess_dir = store._get_session_dir(session_id)
    (sess_dir / art_ref.path).unlink()

    audit_res_after = store.verify_store_consistency(session_id=session_id)
    assert audit_res_after["is_consistent"] is False
    assert art_ref.path in audit_res_after["missing_artifacts"]


# =====================================================================
# Category K: Orphan Database Row Detection
# =====================================================================
def test_category_k_orphan_database_row(store_env):
    store, _, _ = store_env
    record = _make_sample_record()
    file_path = store.save_evidence(record)

    # Delete file directly on disk
    file_path.unlink()

    audit_res = store.verify_store_consistency(session_id=record.session_id)
    assert audit_res["is_consistent"] is False
    assert str(record.evidence_id) in audit_res["missing_records"]


# =====================================================================
# Category L: Schema Mismatch Detection
# =====================================================================
def test_category_l_schema_mismatch_corrupted_json(store_env):
    store, _, _ = store_env
    record = _make_sample_record()
    file_path = store.save_evidence(record)

    # Corrupt JSON syntax
    file_path.write_text("{This is not valid JSON content!!!", encoding="utf-8")

    with pytest.raises(CorruptedArtifactError):
        store.get_evidence(record.evidence_id)


# =====================================================================
# Category M: Forward Compatible Extra Fields
# =====================================================================
def test_category_m_forward_compatible_extra_fields(store_env):
    store, _, _ = store_env
    record = _make_sample_record()
    file_path = store.save_evidence(record)

    # Add forward-compatible extra field
    data = json.loads(file_path.read_text(encoding="utf-8"))
    data["future_quantum_signature"] = "qsig_test_123"
    # Overwrite file and update hash in DB
    new_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
    file_path.write_text(new_json, encoding="utf-8")
    with store.db_manager.transaction() as cur:
        cur.execute(
            "UPDATE evidence_records SET content_hash = ?, record_json = ? WHERE evidence_id = ?;",
            (sha256_bytes(new_json.encode("utf-8")), new_json, str(record.evidence_id)),
        )

    # Forward compatible extra="ignore" allows parsing
    loaded = store.get_evidence(record.evidence_id, verify_integrity=True)
    assert loaded is not None
    assert loaded.evidence_id == record.evidence_id


# =====================================================================
# Category N: Content Validation Enforcement
# =====================================================================
def test_category_n_content_validation_enforcement(store_env):
    store, _, _ = store_env

    # Record with zero content payload fields (all None)
    empty_record = EvidenceRecord(
        evidence_id=uuid4(),
        finding_id=uuid4(),
        session_id=uuid4(),
        evidence_type=EvidenceType.STATISTICAL,
        metrics=None,
        artifacts=None,
        baseline_comparison=None,
        raw_data_ref=None,
        narrative="Empty record test",
        methodology="Test procedure",
    )

    # Must be strictly rejected with SchemaValidationError
    with pytest.raises(SchemaValidationError) as exc:
        store.save_evidence(empty_record)
    assert "must contain at least one content payload" in str(exc.value)

    # With content: must succeed
    empty_record.metrics = {"metric_test": 1.0}
    path = store.save_evidence(empty_record)
    assert path.is_file()


# =====================================================================
# Category O: Concurrent Multi-Thread Writes
# =====================================================================
def test_category_o_concurrent_thread_writes(store_env):
    store, _, _ = store_env
    session_id = uuid4()
    num_threads = 8

    def write_worker(idx: int):
        rec = EvidenceRecord(
            finding_id=uuid4(),
            session_id=session_id,
            evidence_type=EvidenceType.BEHAVIORAL,
            metrics={f"worker_metric_{idx}": float(idx)},
            narrative=f"Concurrent thread {idx} execution",
            methodology="Parallel thread dispatch",
        )
        return store.save_evidence(rec)

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(write_worker, i) for i in range(num_threads)]
        paths = [f.result() for f in futures]

    assert len(paths) == num_threads
    for p in paths:
        assert p.is_file()

    records = store.list_evidence_for_session(session_id)
    assert len(records) == num_threads


# =====================================================================
# Category P: Restart Persistence (Zero Glob Verification)
# =====================================================================
def test_category_p_restart_persistence(temp_dir: Path):
    db_path = temp_dir / "restart_meta.db"
    ev_dir = temp_dir / "restart_store"

    # 1. First process run
    db1 = DatabaseManager(db_path)
    store1 = EvidenceStore(base_dir=ev_dir, db_manager=db1, enforce_content=True)
    rec = _make_sample_record()
    store1.save_evidence(rec)
    store1.close()
    db1.close()

    # 2. Simulate process restart: re-open from same paths
    db2 = DatabaseManager(db_path)
    store2 = EvidenceStore(base_dir=ev_dir, db_manager=db2, enforce_content=True)

    # Retrieval works immediately via SQLite index without glob
    fetched = store2.get_evidence(rec.evidence_id, verify_integrity=True)
    assert fetched is not None
    assert fetched.evidence_id == rec.evidence_id
    assert fetched.metrics["anomaly_score"] == rec.metrics["anomaly_score"]

    store2.close()
    db2.close()


# =====================================================================
# Category Q: 100% Air-Gap Execution
# =====================================================================
def test_category_q_air_gap_execution(temp_dir: Path, monkeypatch):
    """Verify that all EvidenceStore operations execute strictly offline without socket access."""
    def forbidden_socket(*args, **kwargs):
        raise RuntimeError("AIR_GAP_VIOLATION: Attempted network socket access during EvidenceStore operation!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    store = EvidenceStore(temp_dir / "airgap_ev", enforce_content=True)
    session_id = uuid4()

    # 1. Save artifact offline
    art_ref = store.save_artifact(
        session_id=session_id,
        rel_path="features/embedding.bin",
        data=b"\x00\x01\x02\x03" * 32,
        media_type="application/octet-stream",
        description="Air-gapped offline embedding",
    )
    assert art_ref is not None

    # 2. Save evidence offline
    rec = EvidenceRecord(
        finding_id=uuid4(),
        session_id=session_id,
        evidence_type=EvidenceType.CRYPTOGRAPHIC,
        artifacts=[art_ref],
        narrative="Air-gap evidence record",
        methodology="Local SHA-256 validation",
    )
    path = store.save_evidence(rec)
    assert path.is_file()

    # 3. Retrieve and verify offline
    fetched = store.get_evidence(rec.evidence_id, verify_integrity=True)
    assert fetched is not None

    store.close()


# =====================================================================
# Category R: Audit Event Emission & Hash Chain Linkage
# =====================================================================
def test_category_r_audit_chain_linkage(store_env):
    store, _, audit = store_env
    session_id = uuid4()

    art_ref = store.save_artifact(
        session_id=session_id,
        rel_path="maps/saliency.png",
        data=b"fake_saliency_png_bytes",
        media_type="image/png",
        description="Saliency map",
    )

    rec = EvidenceRecord(
        finding_id=uuid4(),
        session_id=session_id,
        evidence_type=EvidenceType.VISUAL,
        artifacts=[art_ref],
        narrative="Audit chain evidence test",
        methodology="Gradient backprop",
    )
    store.save_evidence(rec)
    store.get_evidence(rec.evidence_id, verify_integrity=True)

    # Verify audit events emitted
    events = audit.read_all_events()
    event_types = [e.event_type for e in events]
    assert AuditEventType.ARTIFACT_STORED in event_types
    assert AuditEventType.EVIDENCE_STORED in event_types
    assert AuditEventType.EVIDENCE_VERIFIED in event_types

    # Verify entire cryptographic hash chain is valid
    chain_result = audit.verify_chain()
    assert chain_result.is_valid is True
    assert chain_result.total_events >= 3


# =====================================================================
# Category S: Provenance Linkage & Relational Queries
# =====================================================================
def test_category_s_provenance_linkage(store_env):
    store, db, _ = store_env
    session_id = uuid4()
    asset_id = uuid4()
    finding_id = uuid4()
    verdict_id = uuid4()

    # 0. Register Asset and Session to satisfy foreign key constraints
    from cvif.core.enums import AssetType, AssetStatus, SessionStatus
    from cvif.core.schemas import AssetRegistration, HashManifest, AnalysisSession

    asset = AssetRegistration(
        asset_id=asset_id,
        asset_type=AssetType.DATASET,
        format="coco",
        hash_manifest=HashManifest(),
        total_size_bytes=1024,
    )
    db.save_asset(asset)

    session = AnalysisSession(
        session_id=session_id,
        asset_id=asset_id,
        status=SessionStatus.COMPLETED,
    )
    db.save_session(session)

    # 1. Register finding in DB
    finding = Finding(
        finding_id=finding_id,
        asset_id=asset_id,
        session_id=session_id,
        threat_id="DT-1",
        category="DATA_INTEGRITY",
        severity=SeverityLevel.HIGH,
        confidence=0.92,
        title="Label perturbation detected",
        description="Flipping patterns in training set",
    )
    db.save_finding(finding)

    # 2. Register evidence linked to finding
    rec = EvidenceRecord(
        finding_id=finding_id,
        session_id=session_id,
        evidence_type=EvidenceType.STATISTICAL,
        metrics={"clean_flip_score": 0.94},
        narrative="Label noise anomaly",
        methodology="Loss difference test",
    )
    store.save_evidence(rec)

    # 3. Register verdict referencing finding
    verdict = AssuranceVerdict(
        verdict_id=verdict_id,
        asset_id=asset_id,
        session_id=session_id,
        composite_risk_score=0.85,
        disposition=Disposition.QUARANTINE,
        contributing_finding_ids=[finding_id],
        summary="Critical data poisoning vulnerability",
    )
    db.save_verdict(verdict)

    # 4. Test relational queries
    by_finding = store.get_evidence_by_finding(finding_id)
    assert len(by_finding) == 1
    assert by_finding[0].evidence_id == rec.evidence_id

    by_verdict = store.get_evidence_for_verdict(verdict_id)
    assert len(by_verdict) == 1
    assert by_verdict[0].evidence_id == rec.evidence_id

    by_threat = store.get_evidence_by_threat_id("DT-1")
    assert len(by_threat) == 1
    assert by_threat[0].evidence_id == rec.evidence_id

    by_category = store.get_evidence_by_category("DATA_INTEGRITY")
    assert len(by_category) == 1
    assert by_category[0].evidence_id == rec.evidence_id


# =====================================================================
# Category T: Deterministic Serialization & Canonical Bytes
# =====================================================================
def test_category_t_deterministic_serialization(store_env):
    rec1 = EvidenceRecord(
        evidence_id=uuid4(),
        finding_id=uuid4(),
        session_id=uuid4(),
        evidence_type=EvidenceType.COMPARATIVE,
        metrics={"diff": 0.12, "alpha": 0.05},
        baseline_comparison={"baseline": 1.0, "observed": 1.12},
        narrative="Canonical test narrative",
        methodology="Difference verification",
        reproducibility_info={"param_b": 2, "param_a": 1},
    )

    # Reconstruct same record
    json_dump = rec1.to_canonical_json()
    rec2 = EvidenceRecord.model_validate_json(json_dump)

    assert rec1.to_canonical_bytes() == rec2.to_canonical_bytes()
    assert sha256_bytes(rec1.to_canonical_bytes()) == sha256_bytes(rec2.to_canonical_bytes())


# =====================================================================
# Anti-Stub Sensitivity Proofs
# =====================================================================
def test_anti_stub_sensitivity_proof(store_env):
    """Prove that real changes to metrics or artifact bytes produce genuinely distinct digests."""
    store, _, _ = store_env
    session_id = uuid4()

    # 1. Sensitivity in metrics
    rec_a = EvidenceRecord(
        finding_id=uuid4(),
        session_id=session_id,
        evidence_type=EvidenceType.STATISTICAL,
        metrics={"score": 0.500000},
        narrative="Sensitivity proof A",
        methodology="Test",
    )
    rec_b = EvidenceRecord(
        finding_id=rec_a.finding_id,
        session_id=session_id,
        evidence_type=EvidenceType.STATISTICAL,
        metrics={"score": 0.500001},  # 1 micro-unit difference
        narrative="Sensitivity proof A",
        methodology="Test",
    )
    hash_a = sha256_bytes(rec_a.to_canonical_bytes())
    hash_b = sha256_bytes(rec_b.to_canonical_bytes())
    assert hash_a != hash_b, "Hash must be sensitive to tiny metric shifts"

    # 2. Sensitivity in artifacts
    art_a = store.save_artifact(session_id, "diff/a.bin", b"A" * 1000, "application/octet-stream", "A")
    art_b = store.save_artifact(session_id, "diff/b.bin", b"A" * 999 + b"B", "application/octet-stream", "B")
    meta_a = store.db_manager.get_evidence_artifact(session_id, art_a.path)
    meta_b = store.db_manager.get_evidence_artifact(session_id, art_b.path)
    assert meta_a["artifact_digest"] != meta_b["artifact_digest"]


# =====================================================================
# Performance Benchmarks: 1, 100, 1000 Records
# =====================================================================
def test_scale_performance_benchmarks(store_env):
    """Benchmark indexed persistence and retrieval for 1, 100, and 1,000 records."""
    store, _, _ = store_env

    # 1. Benchmark 1 Record
    s1 = uuid4()
    r1 = _make_sample_record(session_id=s1)
    t0 = time.perf_counter()
    store.save_evidence(r1)
    save_time_1 = time.perf_counter() - t0
    t0 = time.perf_counter()
    res1 = store.get_evidence(r1.evidence_id, verify_integrity=True)
    get_time_1 = time.perf_counter() - t0
    assert res1 is not None

    # 2. Benchmark 100 Records
    s100 = uuid4()
    t0 = time.perf_counter()
    for i in range(100):
        rec = EvidenceRecord(
            finding_id=uuid4(),
            session_id=s100,
            evidence_type=EvidenceType.STATISTICAL,
            metrics={"idx": float(i), "val": 0.5},
            narrative=f"Benchmark record {i}",
            methodology="Benchmarking",
        )
        store.save_evidence(rec)
    save_time_100 = time.perf_counter() - t0

    t0 = time.perf_counter()
    listed_100 = store.list_evidence_for_session(s100)
    query_time_100 = time.perf_counter() - t0
    assert len(listed_100) == 100
    assert query_time_100 < 0.05, f"100 indexed reads took {query_time_100*1000:.2f}ms, expected < 50ms"

    # 3. Benchmark 1,000 Records (indexed batch query)
    s1000 = uuid4()
    t0 = time.perf_counter()
    for i in range(1000):
        rec = EvidenceRecord(
            finding_id=uuid4(),
            session_id=s1000,
            evidence_type=EvidenceType.STATISTICAL,
            metrics={"idx": float(i)},
            narrative=f"Scale 1000 record {i}",
            methodology="High-scale benchmark",
        )
        store.save_evidence(rec)
    save_time_1000 = time.perf_counter() - t0

    t0 = time.perf_counter()
    listed_1000 = store.list_evidence_for_session(s1000)
    query_time_1000 = time.perf_counter() - t0
    assert len(listed_1000) == 1000
    # Indexed query for 1,000 records must complete in < 50ms
    assert query_time_1000 < 0.05, f"1,000 indexed reads took {query_time_1000*1000:.2f}ms, target < 50ms"
