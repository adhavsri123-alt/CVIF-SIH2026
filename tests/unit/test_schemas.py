"""Unit tests for CVIF core schemas and deterministic serialization."""

from datetime import datetime, timezone
import json
import pytest
from uuid import uuid4
from pydantic import ValidationError

from cvif.core.enums import (
    AssetStatus,
    AssetType,
    AuditEventType,
    Disposition,
    EvidenceType,
    ModelTask,
    RecordOrigin,
    SeverityLevel,
)
from cvif.core.schemas import (
    AnalysisSession,
    ArtifactReference,
    AssetFileManifestEntry,
    AssetRegistration,
    AssuranceVerdict,
    AuditEvent,
    ClassificationOutput,
    DetectionOutput,
    EvidenceRecord,
    Finding,
    HashManifest,
    InferenceRecord,
    PredictionResult,
    SegmentationOutput,
    ShiftAssessment,
    ShiftDimensionResult,
    ShiftReport,
    ValidationResult,
)


def test_evidence_record_valid():
    session_id = uuid4()
    finding_id = uuid4()
    record = EvidenceRecord(
        finding_id=finding_id,
        session_id=session_id,
        evidence_type=EvidenceType.STATISTICAL,
        metrics={"ks_p_value": 0.001, "earth_movers_dist": 0.34},
        narrative="Significant distribution shift observed in evaluation partition",
        methodology="Two-sample Kolmogorov-Smirnov test over channel histograms",
    )
    assert record.schema_version == "1.0"
    assert record.evidence_type == EvidenceType.STATISTICAL
    assert record.metrics["ks_p_value"] == 0.001

    canonical = record.to_canonical_json()
    assert isinstance(canonical, str)
    assert "ks_p_value" in canonical


def test_evidence_record_deterministic_canonical_bytes():
    rec1 = EvidenceRecord(
        finding_id=uuid4(),
        session_id=uuid4(),
        evidence_type=EvidenceType.CRYPTOGRAPHIC,
        narrative="Hash verification verified",
        methodology="SHA256 Manifest Check",
    )
    rec2 = EvidenceRecord.model_validate_json(rec1.to_canonical_json())
    assert rec1.to_canonical_bytes() == rec2.to_canonical_bytes()


def test_finding_schema_and_validation():
    finding = Finding(
        asset_id=uuid4(),
        session_id=uuid4(),
        threat_id="DT-1",
        category="DATA_INTEGRITY",
        severity=SeverityLevel.HIGH,
        confidence=0.88,
        title="Trigger Patch Detected",
        description="Suspicious 16x16 square patch identified in bottom right corner.",
        affected_assets=["sample_001.png", "sample_045.png"],
        recommended_disposition=Disposition.QUARANTINE,
    )
    assert finding.severity == SeverityLevel.HIGH
    assert finding.confidence == 0.88
    assert finding.schema_version == "1.0"

    # Confidence must be between 0.0 and 1.0
    with pytest.raises(ValidationError):
        Finding(
            asset_id=uuid4(),
            session_id=uuid4(),
            threat_id="DT-1",
            category="DATA_INTEGRITY",
            severity=SeverityLevel.LOW,
            confidence=1.5,  # Invalid
            title="Bad confidence",
            description="Test",
        )


def test_asset_registration_and_manifest():
    manifest = HashManifest(
        algorithm="sha256",
        entries=[
            AssetFileManifestEntry(
                path="data/train.csv",
                digest="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                size_bytes=0,
            )
        ],
    )
    asset = AssetRegistration(
        asset_type=AssetType.DATASET,
        format="coco",
        file_paths=["data/train.csv"],
        hash_manifest=manifest,
        total_size_bytes=1024,
    )
    assert asset.status == AssetStatus.REGISTERED
    assert asset.schema_version == "1.0"
    assert len(asset.hash_manifest.entries) == 1


def test_assurance_verdict_schema():
    verdict = AssuranceVerdict(
        asset_id=uuid4(),
        session_id=uuid4(),
        composite_risk_score=0.75,
        disposition=Disposition.QUARANTINE,
        summary="High risk of backdoor compromise based on 3 correlated findings.",
        unsupported_checks=["activation_clustering"],
    )
    assert verdict.composite_risk_score == 0.75
    assert verdict.disposition == Disposition.QUARANTINE
    assert "activation_clustering" in verdict.unsupported_checks


def test_inference_record_payload():
    record = InferenceRecord(
        input_image_hash="a" * 64,
        model_id="recon_yolo_v8",
        model_weight_digest="b" * 64,
        preprocessing_config_hash="c" * 64,
        inference_config={"conf_thresh": 0.5},
        output={"detections": [{"bbox": [0.1, 0.1, 0.4, 0.4], "class": "vehicle"}]},
        binding_hmac="d" * 64,
        sequence_number=1,
        nonce="random_nonce_12345",
    )
    payload_bytes = record.compute_canonical_payload()
    assert isinstance(payload_bytes, bytes)
    parsed = json.loads(payload_bytes.decode("utf-8"))
    assert parsed["input_image_hash"] == "a" * 64
    assert parsed["model_id"] == "recon_yolo_v8"


def test_audit_event_hash_calculation():
    event = AuditEvent(
        event_type=AuditEventType.SYSTEM_STARTED,
        actor="system_daemon",
        details={"version": "0.1.0"},
        previous_event_hash="0" * 64,
    )
    computed = event.compute_hash()
    assert len(computed) == 64
    event.event_hash = computed
    assert event.compute_hash() == computed


def test_prediction_result_classification():
    result = PredictionResult(
        task_type=ModelTask.CLASSIFICATION,
        classification=ClassificationOutput(
            class_id=3,
            class_name="tank",
            confidence=0.92,
            top_k=[{"class_id": 3, "class_name": "tank", "confidence": 0.92}],
        ),
    )
    assert result.task_type == ModelTask.CLASSIFICATION
    assert result.classification.confidence == 0.92


def test_prediction_result_detection_validation():
    # Valid detection
    det = DetectionOutput(
        bbox=[0.1, 0.2, 0.6, 0.8],
        class_id=1,
        class_name="armored_vehicle",
        confidence=0.85,
    )
    assert det.bbox == [0.1, 0.2, 0.6, 0.8]

    # Invalid detection: x_max < x_min
    with pytest.raises(ValidationError):
        DetectionOutput(
            bbox=[0.7, 0.2, 0.4, 0.8],
            class_id=1,
            class_name="target",
            confidence=0.85,
        )

    # Invalid detection: out-of-bounds coordinates
    with pytest.raises(ValidationError):
        DetectionOutput(
            bbox=[-0.1, 0.2, 0.5, 0.8],
            class_id=1,
            class_name="target",
            confidence=0.85,
        )


def test_shift_report_schema():
    report = ShiftReport(
        reference_asset_id=uuid4(),
        evaluation_asset_id=uuid4(),
        session_id=uuid4(),
        overall_distance=0.45,
        dimensions={
            "pixel_intensity": ShiftDimensionResult(
                detected=True, metric_value=0.42, p_value=0.002, description="Mean shift"
            )
        },
        assessment=ShiftAssessment(
            natural_drift_likelihood=0.15,
            suspicious_manipulation_likelihood=0.85,
            evidence_sufficient=True,
            reasoning="Anomalous localized clustering incompatible with seasonal camera drift",
        ),
        characterization="Suspicious Targeted Distribution Manipulation",
    )
    assert report.overall_distance == 0.45
    assert report.assessment.suspicious_manipulation_likelihood == 0.85
