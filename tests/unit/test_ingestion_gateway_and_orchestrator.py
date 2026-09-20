"""Integration tests for IngestionGateway and DatasetIntegrityOrchestrator."""

import json
from pathlib import Path
import pytest

from cvif.analysis.orchestrator import DatasetIntegrityOrchestrator
from cvif.core.enums import AssetStatus, AuditEventType, SessionStatus
from cvif.crypto.chain import verify_audit_chain
from cvif.features.statistical import StatisticalFeatureExtractor
from cvif.ingestion.gateway import IngestionGateway


def test_end_to_end_gateway_and_orchestrator(temp_dir: Path, make_png, db_manager, audit_logger, evidence_store):
    """Test full pipeline: IngestionGateway registers asset & logs audit -> Orchestrator runs battery & stores evidence."""
    # 1. Create realistic COCO dataset
    ds_dir = temp_dir / "recon_dataset"
    ds_dir.mkdir()
    img_dir = ds_dir / "images"
    img_dir.mkdir()

    for i in range(10):
        (img_dir / f"frame_{i}.png").write_bytes(make_png(width=128, height=128, fill_byte=30 + i * 5))

    coco_data = {
        "info": {
            "description": "Tactical Field Reconnaissance",
            "contributor": "Forward_Observer_Unit_4",
        },
        "categories": [
            {"id": 0, "name": "military_truck"},
            {"id": 1, "name": "command_bunker"},
        ],
        "images": [
            {"id": i, "file_name": f"images/frame_{i}.png", "width": 128, "height": 128}
            for i in range(10)
        ],
        "annotations": [
            {
                "id": 100 + i,
                "image_id": i,
                "category_id": i % 2,
                "bbox": [10, 10, 50, 50],
                "area": 2500.0,
                "iscrowd": 0,
            }
            for i in range(10)
        ],
    }
    ann_file = ds_dir / "annotations.json"
    ann_file.write_text(json.dumps(coco_data), encoding="utf-8")

    # 2. Ingest via IngestionGateway
    gateway = IngestionGateway(audit_logger=audit_logger, db_manager=db_manager)
    unified, val_res, asset_reg = gateway.ingest_dataset(
        dataset_path=ds_dir,
        batch_id="Batch_Alpha_2026",
    )

    assert val_res.is_valid is True
    assert unified.contributor_id == "Forward_Observer_Unit_4"
    assert unified.batch_id == "Batch_Alpha_2026"
    assert len(unified.images) == 10
    assert asset_reg.status == AssetStatus.REGISTERED

    # Verify registration stored in database
    db_asset = db_manager.get_asset(unified.asset_id)
    assert db_asset is not None
    assert db_asset.asset_id == unified.asset_id
    assert db_asset.metadata["total_images"] == 10

    # 3. Run Analysis Battery via DatasetIntegrityOrchestrator
    orchestrator = DatasetIntegrityOrchestrator(
        feature_extractor=StatisticalFeatureExtractor(),
        evidence_store=evidence_store,
        audit_logger=audit_logger,
        db_manager=db_manager,
    )

    session = orchestrator.run_analysis(
        dataset=unified,
        operator_id="Operator_DGIS_99",
    )

    assert session.status == SessionStatus.COMPLETED
    assert session.asset_id == unified.asset_id
    assert session.duration_ms >= 0.0
    assert "DT-4" in session.executed_analyses
    assert "DT-1" in session.executed_analyses
    assert "DT-2" in session.executed_analyses
    assert "DT-3" in session.executed_analyses
    assert "DT-5" in session.executed_analyses
    assert "DT-6" in session.executed_analyses

    # Verify session persisted in database
    db_session = db_manager.get_session(session.session_id)
    assert db_session is not None
    assert db_session.status == SessionStatus.COMPLETED

    # Verify audit events emitted in chronological sequence with monotonic sequence_number
    events = audit_logger.read_all_events()
    event_types = [e.event_type for e in events]
    assert AuditEventType.ASSET_INGESTED in event_types
    assert AuditEventType.ANALYSIS_STARTED in event_types
    assert AuditEventType.ANALYSIS_COMPLETED in event_types

    # Cryptographic audit hash chain verification
    chain_res = verify_audit_chain(events)
    assert chain_res.is_valid is True
    assert chain_res.error_message is None




def test_gateway_unsupported_format_rejection(temp_dir: Path):
    """Test gateway cleanly rejects unsupported or arbitrary directory structure."""
    empty_dir = temp_dir / "random_empty"
    empty_dir.mkdir()
    gateway = IngestionGateway()

    from cvif.core.exceptions import CVIFFormatError
    with pytest.raises(CVIFFormatError, match="Unsupported dataset format"):
        gateway.ingest_dataset(empty_dir)
