"""Unit tests for EvidenceStore write-once immutability and artifact management."""

from pathlib import Path
import pytest
from uuid import uuid4

from cvif.core.enums import EvidenceType
from cvif.core.exceptions import EvidenceImmutableError
from cvif.core.schemas import EvidenceRecord
from cvif.evidence.store import EvidenceStore


def test_evidence_store_write_once_immutability(temp_dir: Path):
    store = EvidenceStore(temp_dir / "ev_store")
    session_id = uuid4()
    finding_id = uuid4()

    record = EvidenceRecord(
        finding_id=finding_id,
        session_id=session_id,
        evidence_type=EvidenceType.STATISTICAL,
        metrics={"anomaly_score": 0.94},
        narrative="Outlier detected in feature activation space",
        methodology="Mahalanobis distance on layer pool5",
    )

    # First write succeeds
    path = store.save_evidence(record)
    assert path.is_file()

    # Second write with same evidence_id MUST fail with EvidenceImmutableError
    with pytest.raises(EvidenceImmutableError):
        store.save_evidence(record)

    # Retrieval
    fetched = store.get_evidence(record.evidence_id)
    assert fetched is not None
    assert fetched.evidence_id == record.evidence_id
    assert fetched.metrics["anomaly_score"] == 0.94


def test_evidence_store_artifacts_and_listing(temp_dir: Path):
    store = EvidenceStore(temp_dir / "ev_store")
    session_id = uuid4()

    # Save visual heatmap artifact
    heatmap_bytes = b"fake_png_header_and_image_data"
    artifact_ref = store.save_artifact(
        session_id=session_id,
        rel_path="heatmaps/trigger_gradcam.png",
        data=heatmap_bytes,
        media_type="image/png",
        description="GradCAM visual attribution highlighting trigger region",
    )
    assert "trigger_gradcam.png" in artifact_ref.path
    assert artifact_ref.media_type == "image/png"

    # Read back artifact
    read_data = store.read_artifact(session_id, artifact_ref.path)
    assert read_data == heatmap_bytes

    # Create and list multiple evidence records
    for i in range(3):
        rec = EvidenceRecord(
            finding_id=uuid4(),
            session_id=session_id,
            evidence_type=EvidenceType.VISUAL,
            narrative=f"Visual test evidence {i}",
            methodology="Saliency map analysis",
        )
        store.save_evidence(rec)

    session_evidence = store.list_evidence_for_session(session_id)
    assert len(session_evidence) == 3
