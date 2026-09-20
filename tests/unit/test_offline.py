"""Air-gap and offline isolation tests proving no external network access is needed or attempted."""

from pathlib import Path
import socket
import pytest
from uuid import uuid4

import cvif
from cvif.core.config import AppConfig
from cvif.core.enums import AssetType, AuditEventType, EvidenceType, ModelTask, SessionStatus
from cvif.core.schemas import AssetRegistration, EvidenceRecord, HashManifest
from cvif.crypto.signing import generate_ed25519_keypair
from cvif.crypto.keystore import KeyStore
from cvif.storage.database import DatabaseManager
from cvif.storage.filestore import SafeFileStore
from cvif.evidence.store import EvidenceStore
from cvif.audit.logger import AuditLogger
from cvif.features.statistical import StatisticalFeatureExtractor
from cvif.model.adapter import MockModelAdapter
from cvif.ingestion.adapters.base import MockDatasetAdapter


def test_core_foundation_strictly_offline(temp_dir: Path, monkeypatch):
    """Verify that all foundational workflows operate with 100% air-gap isolation without network calls."""
    # 1. Prohibit any socket operations
    def forbidden_socket(*args, **kwargs):
        raise RuntimeError("AIR_GAP_VIOLATION: Attempted socket connection!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    # 2. Config & Path resolution
    cfg = AppConfig().resolve_paths(temp_dir)
    assert cfg.system.air_gapped is True

    # 3. Cryptographic key management
    priv_key, pub_key = generate_ed25519_keypair()
    keystore = KeyStore(temp_dir / "truststore.json")
    keystore.register_public_key("local_sensor_1", "Field Unit Alpha", pub_key)
    keystore.register_hmac_secret("local_hmac_1", "Field Unit Alpha", b"offline_secret_key")
    assert keystore.check_key_validity("local_sensor_1")[0] is True

    # 4. Storage & Database operations
    db = DatabaseManager(temp_dir / "offline.db")
    asset = AssetRegistration(
        asset_id=uuid4(),
        asset_type=AssetType.DATASET,
        format="coco",
        hash_manifest=HashManifest(),
        total_size_bytes=1000,
    )
    db.save_asset(asset)
    assert db.get_asset(asset.asset_id) is not None

    file_store = SafeFileStore(temp_dir / "assets")
    digest, path = file_store.store_content_addressed(b"untrusted_image_bytes")
    assert file_store.exists(path)

    # 5. Audit log operations and chain verification
    audit = AuditLogger(temp_dir / "offline_audit.jsonl")
    ev1 = audit.log_event(AuditEventType.SYSTEM_STARTED, actor="offline_operator", signing_key=priv_key)
    ev2 = audit.log_event(AuditEventType.ASSET_INGESTED, actor="offline_operator", asset_id=asset.asset_id)
    verify_res = audit.verify_chain()
    assert verify_res.is_valid is True
    assert verify_res.total_events == 2

    # 6. Evidence store write-once persistence
    ev_store = EvidenceStore(temp_dir / "offline_evidence")
    ev_rec = EvidenceRecord(
        finding_id=uuid4(),
        session_id=uuid4(),
        evidence_type=EvidenceType.STATISTICAL,
        narrative="Air-gap test evidence record",
        methodology="Local offline feature analysis",
    )
    ev_path = ev_store.save_evidence(ev_rec)
    assert ev_path.is_file()
    assert ev_store.get_evidence(ev_rec.evidence_id) is not None

    # 7. Statistical feature extractor
    extractor = StatisticalFeatureExtractor(dim=128)
    embedding = extractor.extract(b"offline_image_byte_stream_sample")
    assert len(embedding) == 128

    # 8. Model and Dataset adapter contracts
    model = MockModelAdapter(task=ModelTask.CLASSIFICATION)
    pred = model.predict(b"dummy_bytes")
    assert pred.classification.confidence > 0

    dataset = MockDatasetAdapter()
    assert dataset.validate().is_valid is True

    db.close()


def test_phase3_ingestion_and_integrity_strictly_offline(temp_dir: Path, monkeypatch, make_png):
    """Verify that COCO/YOLO ingestion, hashing, and all DT-1 to DT-6 checks execute strictly offline without network."""
    def forbidden_socket(*args, **kwargs):
        raise RuntimeError("AIR_GAP_VIOLATION: Attempted socket connection during Phase 3 analysis!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    import json
    from cvif.ingestion.gateway import IngestionGateway
    from cvif.analysis.orchestrator import DatasetIntegrityOrchestrator

    ds_dir = temp_dir / "airgap_ds"
    ds_dir.mkdir()
    (ds_dir / "images").mkdir()

    for i in range(10):
        (ds_dir / "images" / f"f_{i}.png").write_bytes(make_png(64, 64, fill_byte=20 + i))

    coco = {
        "info": {"contributor": "AirGap_Field_Team"},
        "categories": [{"id": 0, "name": "c0"}, {"id": 1, "name": "c1"}],
        "images": [{"id": i, "file_name": f"images/f_{i}.png", "width": 64, "height": 64} for i in range(10)],
        "annotations": [{"id": i, "image_id": i, "category_id": i % 2, "bbox": [5, 5, 20, 20]} for i in range(10)],
    }
    (ds_dir / "annotations.json").write_text(json.dumps(coco), encoding="utf-8")

    gateway = IngestionGateway()
    unified, val, _ = gateway.ingest_dataset(ds_dir)
    assert val.is_valid is True

    orchestrator = DatasetIntegrityOrchestrator()
    session = orchestrator.run_analysis(unified)
    assert session.status == SessionStatus.COMPLETED
    assert len(session.executed_analyses) >= 5


def test_phase4_model_integrity_strictly_offline(temp_dir: Path, monkeypatch):
    """Verify that model safety, battery execution, MT-1 to MT-4, fingerprinting, and DB/evidence persist strictly offline."""
    def forbidden_socket(*args, **kwargs):
        raise RuntimeError("AIR_GAP_VIOLATION: Attempted socket connection during Phase 4 analysis!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    from cvif.analysis.model_orchestrator import ModelIntegrityOrchestrator
    from cvif.audit.logger import AuditLogger
    from cvif.core.enums import ModelAccessLevel, ModelTask
    from cvif.evidence.store import EvidenceStore
    from cvif.model.adapter import MockModelAdapter
    from cvif.model.battery import ReferenceBatteryBuilder
    from cvif.model.safety import ModelSafetyScanner
    from cvif.storage.database import DatabaseManager

    # 1. Model safety pre-flight scanning offline
    dummy_onnx = temp_dir / "offline_model.onnx"
    dummy_onnx.write_bytes(b"\x08\x01\x12\x04test" + b"\x00" * 200)
    safety_res = ModelSafetyScanner().scan(dummy_onnx)
    assert safety_res.is_safe is True

    # 2. Reference battery generation and hashing offline
    battery = ReferenceBatteryBuilder.create_synthetic_battery(
        task_type=ModelTask.CLASSIFICATION,
        output_dir=temp_dir / "airgap_battery",
    )
    assert battery.battery_hash is not None

    # 3. Full ModelIntegrityOrchestrator execution offline
    ev_store = EvidenceStore(temp_dir / "evidence")
    audit_logger = AuditLogger(temp_dir / "audit.jsonl")
    db_mgr = DatabaseManager(temp_dir / "model_integrity.db")

    orchestrator = ModelIntegrityOrchestrator(
        evidence_store=ev_store,
        audit_logger=audit_logger,
        db_manager=db_mgr,
    )

    m_cand = MockModelAdapter(task=ModelTask.CLASSIFICATION, access_level=ModelAccessLevel.WHITE_BOX)
    m_ref = MockModelAdapter(task=ModelTask.CLASSIFICATION, access_level=ModelAccessLevel.WHITE_BOX)

    session = orchestrator.run_analysis(
        candidate_model=m_cand,
        reference_model=m_ref,
        battery=battery,
        operator_id="AirGap_Security_Officer",
    )

    assert session.status == SessionStatus.COMPLETED
    assert len(session.executed_analyses) == 4
    assert len(session.findings) >= 1

    # Verify database and audit chain
    db_session = db_mgr.get_session(session.session_id)
    assert db_session is not None
    assert audit_logger.verify_chain().is_valid is True

    db_mgr.close()


def test_phase5_provenance_strictly_offline(temp_dir: Path, monkeypatch):
    """Verify that Phase 5 generation, verification, DB replay, and orchestrator execute strictly offline without network."""
    def forbidden_socket(*args, **kwargs):
        raise RuntimeError("AIR_GAP_VIOLATION: Attempted socket connection during Phase 5 provenance analysis!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    from cvif.analysis.inference_provenance.orchestrator import InferenceProvenanceOrchestrator
    from cvif.audit.logger import AuditLogger
    from cvif.crypto.keystore import KeyStore
    from cvif.crypto.signing import generate_ed25519_keypair
    from cvif.provenance.generator import InferenceProvenanceGenerator
    from cvif.provenance.verifier import InferenceProvenanceVerifier
    from cvif.storage.database import DatabaseManager

    ks = KeyStore(temp_dir / "airgap_p5_ks.json")
    db = DatabaseManager(temp_dir / "airgap_p5.db")
    audit = AuditLogger(temp_dir / "airgap_p5_audit.jsonl")

    priv, pub = generate_ed25519_keypair()
    ks.register_public_key("OFFLINE-UAV-KEY-01", "AirGap Sqdn Alpha", pub)

    gen = InferenceProvenanceGenerator(signing_key_id="OFFLINE-UAV-KEY-01", private_key=priv)
    record = gen.generate(
        input_image=b"offline_raw_image_frame_data_999",
        model_id="offline_yolo_recon",
        model_weight_digest="12" * 32,
        output={"detections": [{"bbox": [0.1, 0.2, 0.3, 0.4], "confidence": 0.99, "class_name": "radar"}]},
    )

    verifier = InferenceProvenanceVerifier(key_store=ks, db_manager=db)
    orchestrator = InferenceProvenanceOrchestrator(verifier=verifier, audit_logger=audit)

    session = orchestrator.verify_and_analyze(record, operator_id="AirGap_Field_Officer")
    assert session.status.value == "COMPLETED"
    assert len(session.executed_analyses) == 3
    assert len(session.findings) == 0

    # Verify audit chain integrity
    assert audit.verify_chain().is_valid is True
    db.close()



