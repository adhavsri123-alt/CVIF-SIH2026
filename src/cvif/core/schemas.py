"""Core Pydantic data schemas for the CVIF architecture (Version 1.0)."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from cvif.core.enums import (
    AssetStatus,
    AssetType,
    AuditEventType,
    BatteryDifficulty,
    Disposition,
    EvidenceType,
    KeyStatus,
    KeyType,
    ModelTask,
    ProvenanceOutcome,
    RecordOrigin,
    SessionStatus,
    SeverityLevel,
)


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class CVIFBaseModel(BaseModel):
    """Base model with forward-compatible parsing and strict configuration."""

    model_config = ConfigDict(
        extra="ignore",  # Forward compatibility: ignore unknown fields in minor versions
        validate_assignment=True,
        populate_by_name=True,
    )

    def to_canonical_json(self) -> str:
        """Produce deterministic JSON with sorted keys and no unnecessary whitespace."""
        data = self.model_dump(mode="json")
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def to_canonical_bytes(self) -> bytes:
        """Produce canonical UTF-8 bytes for hashing or HMAC/signing."""
        return self.to_canonical_json().encode("utf-8")


# =====================================================================
# I.3 Evidence & Artifact Schemas
# =====================================================================


class ArtifactReference(CVIFBaseModel):
    """Reference to a physical artifact stored within the evidence store."""

    path: str = Field(..., description="Relative path within evidence store session artifacts")
    media_type: str = Field(..., description="MIME type, e.g. image/png, application/json")
    description: str = Field(..., description="Human-readable description of artifact contents")


class EvidenceRecord(CVIFBaseModel):
    """Canonical evidence record linked to an assurance finding."""

    evidence_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID = Field(..., description="Parent finding UUID")
    session_id: UUID = Field(..., description="Associated analysis session context")
    evidence_type: EvidenceType

    metrics: Optional[Dict[str, float]] = Field(
        default=None, description="Quantitative statistical metrics"
    )
    artifacts: Optional[List[ArtifactReference]] = Field(
        default=None, description="Visual/data artifact references"
    )
    baseline_comparison: Optional[Dict[str, Any]] = Field(
        default=None, description="Expected baseline vs. actual observed values"
    )
    raw_data_ref: Optional[str] = Field(
        default=None, description="Relative path to raw diagnostic dump"
    )

    narrative: str = Field(..., description="Human-readable explanation of what evidence indicates")
    methodology: str = Field(..., description="Algorithm or procedure used to produce evidence")
    reproducibility_info: Dict[str, Any] = Field(
        default_factory=dict, description="Seeds, parameters, and environment context"
    )

    timestamp: datetime = Field(default_factory=utc_now)
    schema_version: str = Field(default="1.0")

    @field_validator("metrics", "artifacts", "baseline_comparison", "raw_data_ref")
    @classmethod
    def check_at_least_one_content(cls, v: Any, info: Any) -> Any:
        # Content verification handled at full record level
        return v


# =====================================================================
# I.2 Finding Schema
# =====================================================================


class Finding(CVIFBaseModel):
    """Individual assurance finding emitted by an analysis check."""

    finding_id: UUID = Field(default_factory=uuid4)
    asset_id: UUID = Field(..., description="Target asset ID under analysis")
    session_id: UUID = Field(..., description="Analysis session context")
    threat_id: str = Field(..., description="Identifier from Threat Taxonomy, e.g., DT-1, MT-3")
    category: str = Field(..., description="DATA_INTEGRITY, MODEL_INTEGRITY, INFERENCE_PROVENANCE, DISTRIBUTION_SHIFT")
    severity: SeverityLevel
    confidence: float = Field(..., ge=0.0, le=1.0, description="Calibrated confidence score [0.0, 1.0]")
    title: str = Field(..., description="Short summary title")
    description: str = Field(..., description="Detailed technical description")
    evidence_ids: List[UUID] = Field(
        default_factory=list, description="Linked EvidenceRecord UUIDs"
    )
    affected_assets: List[str] = Field(
        default_factory=list, description="Specific sample IDs, layer names, or classes affected"
    )
    recommended_disposition: Disposition = Field(
        default=Disposition.REVIEW, description="Recommended disposition based on this finding"
    )
    limitations: List[str] = Field(
        default_factory=list, description="Explicit statement of what this check could NOT verify"
    )
    timestamp: datetime = Field(default_factory=utc_now)
    schema_version: str = Field(default="1.0")


# =====================================================================
# I.1 Asset Registration & Manifest Schemas
# =====================================================================


class AssetFileManifestEntry(CVIFBaseModel):
    """Individual file digest entry in asset manifest."""

    path: str = Field(..., description="Path relative to asset root")
    digest: str = Field(..., description="SHA-256 hex digest of file")
    size_bytes: int = Field(..., ge=0)


class HashManifest(CVIFBaseModel):
    """Cryptographic manifest of all constituent files in an asset."""

    algorithm: str = Field(default="sha256")
    entries: List[AssetFileManifestEntry] = Field(default_factory=list)


class AssetRegistration(CVIFBaseModel):
    """Registration record for an untrusted asset in the catalog."""

    asset_id: UUID = Field(default_factory=uuid4)
    asset_type: AssetType
    format: str = Field(..., description="Format origin, e.g. coco, yolo, onnx, pytorch, torchscript")
    file_paths: List[str] = Field(default_factory=list)
    hash_manifest: HashManifest
    total_size_bytes: int = Field(..., ge=0)
    ingestion_timestamp: datetime = Field(default_factory=utc_now)
    contributor_id: Optional[str] = None
    batch_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    status: AssetStatus = Field(default=AssetStatus.REGISTERED)
    schema_version: str = Field(default="1.0")


# =====================================================================
# I.4 Assurance Verdict Schema
# =====================================================================


class AssuranceVerdict(CVIFBaseModel):
    """Synthesized assurance verdict aggregating all findings for an asset."""

    verdict_id: UUID = Field(default_factory=uuid4)
    asset_id: UUID
    session_id: UUID
    composite_risk_score: float = Field(..., ge=0.0, le=1.0)
    disposition: Disposition
    contributing_finding_ids: List[UUID] = Field(default_factory=list)
    summary: str = Field(..., description="High-level narrative assessment")
    unsupported_checks: List[str] = Field(
        default_factory=list, description="Checks skipped due to format/access constraints"
    )
    timestamp: datetime = Field(default_factory=utc_now)
    schema_version: str = Field(default="1.0")


# =====================================================================
# I.5 Inference Record & Provenance Schemas
# =====================================================================


class InferenceRecord(CVIFBaseModel):
    """Cryptographically bound record of a model inference operation."""

    record_id: UUID = Field(default_factory=uuid4)
    session_id: UUID = Field(default_factory=uuid4, description="Session context identifier")
    producer_id: Optional[str] = Field(
        default=None, description="Producer unit, drone, or sensor identity"
    )
    origin: RecordOrigin = Field(default=RecordOrigin.EXTERNAL)
    input_image_hash: str = Field(..., description="SHA-256 hex digest of raw input image")
    model_id: str = Field(..., description="Model identifier name/tag")
    model_weight_digest: str = Field(..., description="SHA-256 hex digest of model weight tensor file")
    preprocessing_config_hash: str = Field(..., description="SHA-256 hex digest of preprocessing config")
    inference_config: Dict[str, Any] = Field(default_factory=dict)
    output: Dict[str, Any] = Field(..., description="Model prediction output dictionary")
    binding_hmac: Optional[str] = Field(
        default=None, description="Optional HMAC-SHA256 binding over canonical payload"
    )
    signing_key_id: Optional[str] = Field(
        default=None, description="Identifier of key used to compute HMAC/signature in KeyStore"
    )
    timestamp: datetime = Field(default_factory=utc_now)
    sequence_number: int = Field(..., ge=0, description="Monotonically increasing sequence number")
    nonce: str = Field(..., description="Unique random string per record")
    previous_record_hash: Optional[str] = Field(
        default=None, description="SHA-256 hex digest of previous record in stream hash chain"
    )
    signature: Optional[str] = Field(
        default=None, description="Optional Ed25519 digital signature hex/b64"
    )
    schema_version: str = Field(default="1.0")

    def compute_canonical_payload(self) -> bytes:
        """Produce the deterministic byte sequence bound by HMAC or signature."""
        from cvif.provenance.canonical import canonical_payload_bytes
        return canonical_payload_bytes(self)

    def compute_record_hash(self) -> str:
        """Compute SHA-256 digest over canonical payload bytes."""
        import hashlib
        return hashlib.sha256(self.compute_canonical_payload()).hexdigest()


class ProvenanceVerificationResult(CVIFBaseModel):
    """Outcome of provenance verification across integrity, replay, and authenticity."""

    status: ProvenanceOutcome
    disposition: Disposition
    is_valid: bool
    record_id: UUID
    session_id: UUID
    signing_key_id: Optional[str] = None
    producer_id: Optional[str] = None
    findings: List[Finding] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    verified_at: datetime = Field(default_factory=utc_now)
    schema_version: str = Field(default="1.0")



# =====================================================================
# I.6 Audit Event Schema
# =====================================================================


class AuditEvent(CVIFBaseModel):
    """Tamper-evident, hash-chained log entry in the system audit trail."""

    event_id: UUID = Field(default_factory=uuid4)
    sequence_number: int = Field(default=0, ge=0, description="Monotonically increasing sequence number")
    timestamp: datetime = Field(default_factory=utc_now)
    event_type: AuditEventType
    actor: str = Field(..., description="User, daemon, or component identity")
    asset_id: Optional[UUID] = None
    session_id: Optional[UUID] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    previous_event_hash: str = Field(
        ..., description="SHA-256 hex digest of the previous event in the chain"
    )
    event_hash: str = Field(
        default="", description="SHA-256 hex digest of this event including previous_event_hash"
    )
    signature: Optional[str] = Field(
        default=None, description="Optional Ed25519 signature over event_hash"
    )
    schema_version: str = Field(default="1.0")

    def compute_hash(self) -> str:
        """Compute SHA-256 hash over canonical representation excluding event_hash and signature."""
        import hashlib

        data = {
            "event_id": str(self.event_id),
            "sequence_number": self.sequence_number,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "actor": self.actor,
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "session_id": str(self.session_id) if self.session_id else None,
            "details": self.details,
            "previous_event_hash": self.previous_event_hash,
            "schema_version": self.schema_version,
        }
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


# =====================================================================
# I.7 Distribution Shift Schemas
# =====================================================================


class ShiftDimensionResult(CVIFBaseModel):
    """Observed metric and characterization for a single shift dimension."""

    detected: bool
    metric_value: float
    p_value: Optional[float] = None
    description: str


class ShiftAssessment(CVIFBaseModel):
    """Calibrated distinction between natural operational drift and suspicious manipulation."""

    natural_drift_likelihood: float = Field(..., ge=0.0, le=1.0)
    suspicious_manipulation_likelihood: float = Field(..., ge=0.0, le=1.0)
    evidence_sufficient: bool = Field(..., description="Whether sample size and separability are sufficient")
    reasoning: str


class ShiftReport(CVIFBaseModel):
    """Comprehensive distribution shift evaluation report."""

    report_id: UUID = Field(default_factory=uuid4)
    reference_asset_id: UUID
    evaluation_asset_id: UUID
    session_id: UUID
    overall_distance: float = Field(..., ge=0.0)
    dimensions: Dict[str, ShiftDimensionResult] = Field(default_factory=dict)
    assessment: ShiftAssessment
    characterization: str
    timestamp: datetime = Field(default_factory=utc_now)
    schema_version: str = Field(default="1.0")


# =====================================================================
# I.8 Prediction Result Schemas (Model-Agnostic Outputs)
# =====================================================================


class ClassificationOutput(CVIFBaseModel):
    """Prediction result for classification models."""

    class_id: int
    class_name: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    top_k: List[Dict[str, Any]] = Field(default_factory=list)
    logits: Optional[List[float]] = None


class DetectionOutput(CVIFBaseModel):
    """Single bounding box prediction for object detection models (e.g. YOLO)."""

    bbox: List[float] = Field(
        ..., min_length=4, max_length=4, description="[x_min, y_min, x_max, y_max] normalized to [0.0, 1.0]"
    )
    class_id: int
    class_name: str
    confidence: float = Field(..., ge=0.0, le=1.0)

    @field_validator("bbox")
    @classmethod
    def validate_normalized_coordinates(cls, v: List[float]) -> List[float]:
        for coord in v:
            if not (0.0 <= coord <= 1.05):  # allow tiny epsilon for rounding
                raise ValueError(f"Bounding box coordinate {coord} must be normalized in [0.0, 1.0]")
        if v[2] < v[0] or v[3] < v[1]:
            raise ValueError(f"Invalid bounding box geometry: x_max ({v[2]}) < x_min ({v[0]}) or y_max < y_min")
        return v


class SegmentationOutput(CVIFBaseModel):
    """Prediction result for segmentation models."""

    mask_ref: str
    class_map: Dict[int, str]
    confidences: Optional[List[float]] = None


class PredictionResult(CVIFBaseModel):
    """Polymorphic container for model predictions across classification and detection."""

    task_type: ModelTask
    status: str = Field(
        default="SUCCESS",
        description="Inference execution status: SUCCESS, RUNTIME_UNAVAILABLE, UNSUPPORTED_RUNTIME, MODEL_LOAD_FAILED, INFERENCE_UNAVAILABLE",
    )
    classification: Optional[ClassificationOutput] = None
    detections: Optional[List[DetectionOutput]] = None
    segmentation: Optional[SegmentationOutput] = None
    raw_output: Optional[Dict[str, Any]] = None
    inference_time_ms: Optional[float] = None

    @field_validator("task_type")
    @classmethod
    def validate_task_payload_consistency(cls, v: ModelTask, info: Any) -> ModelTask:
        # Validated post-creation based on task_type
        return v


# =====================================================================
# I.10 Analysis Session Schema
# =====================================================================


class AnalysisSession(CVIFBaseModel):
    """State and summary of an end-to-end analysis execution session."""

    session_id: UUID = Field(default_factory=uuid4)
    asset_id: UUID
    status: SessionStatus = Field(default=SessionStatus.INITIALIZING)
    requested_analyses: List[str] = Field(default_factory=list)
    executed_analyses: List[str] = Field(default_factory=list)
    skipped_analyses: List[Dict[str, str]] = Field(default_factory=list)
    start_time: datetime = Field(default_factory=utc_now)
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    findings: List[Finding] = Field(default_factory=list)
    verdict: Optional[AssuranceVerdict] = None
    operator_id: Optional[str] = None
    execution_environment: Dict[str, Any] = Field(default_factory=dict)
    schema_version: str = Field(default="1.0")


# =====================================================================
# I.11 Validation Result Schema
# =====================================================================


class ValidationResult(CVIFBaseModel):
    """Validation outcome for an ingested dataset or model structure."""

    is_valid: bool
    format_detected: str
    total_samples: int = Field(default=0, ge=0)
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    stats: Dict[str, Any] = Field(default_factory=dict)


# =====================================================================
# KeyStore Record Schema
# =====================================================================


class KeyRecord(CVIFBaseModel):
    """Metadata and status of a cryptographic key in the local Trust Store."""

    key_id: str
    key_type: KeyType
    owner_entity: str
    public_key_hex: Optional[str] = None
    status: KeyStatus = Field(default=KeyStatus.ACTIVE)
    valid_from: datetime = Field(default_factory=utc_now)
    valid_until: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utc_now)


# =====================================================================
# J.2 Unified Dataset Representation Schemas
# =====================================================================


class ImageRecord(CVIFBaseModel):
    """Normalized metadata and cryptographic digest for an ingested image file."""

    image_id: str
    file_path: str = Field(..., description="Relative path from dataset root using forward slashes")
    file_hash: str = Field(..., description="SHA-256 hex digest of raw image file")
    width: int = Field(default=0, ge=0)
    height: int = Field(default=0, ge=0)
    channels: int = Field(default=3, ge=1)
    file_size_bytes: int = Field(default=0, ge=0)
    source_metadata: Optional[Dict[str, Any]] = Field(
        default=None, description="EXIF, contributor, acquisition conditions, or origin tags"
    )


class AnnotationRecord(CVIFBaseModel):
    """Normalized object bounding box and classification annotation."""

    annotation_id: str
    image_id: str
    class_id: int = Field(..., ge=0)
    class_name: str
    # Bounding box coordinates normalized to [0.0, 1.05] as [x_min, y_min, x_max, y_max]
    bbox: Optional[List[float]] = Field(
        default=None,
        description="[x_min, y_min, x_max, y_max] normalized coordinates in range [0.0, 1.05]",
    )
    area: Optional[float] = Field(default=None, ge=0.0)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    iscrowd: int = Field(default=0)
    segmentation: Optional[Any] = None
    origin: Optional[str] = Field(default=None, description="Originator or model tag if present")

    @field_validator("bbox")
    @classmethod
    def validate_normalized_bbox(cls, v: Optional[List[float]]) -> Optional[List[float]]:
        if v is None:
            return v
        if len(v) != 4:
            raise ValueError(f"Expected 4 bounding box coordinates, got {len(v)}")
        for coord in v:
            if not (0.0 <= coord <= 1.05):
                raise ValueError(f"Bounding box coordinate {coord} must be normalized in [0.0, 1.05]")
        if v[2] < v[0] or v[3] < v[1]:
            raise ValueError(f"Invalid bounding box geometry: x_max ({v[2]}) < x_min ({v[0]}) or y_max < y_min")
        return v


class ClassInfo(CVIFBaseModel):
    """Information and sample/instance count for an annotated class."""

    class_id: int = Field(..., ge=0)
    class_name: str
    count: int = Field(default=0, ge=0)


class UnifiedDataset(CVIFBaseModel):
    """Canonical, model-agnostic dataset representation for all ingestion formats."""

    asset_id: UUID = Field(default_factory=uuid4)
    dataset_root: str
    format_origin: str = Field(..., description="Ingestion format: 'coco' or 'yolo'")
    images: List[ImageRecord] = Field(default_factory=list)
    classes: List[ClassInfo] = Field(default_factory=list)
    annotations: List[AnnotationRecord] = Field(default_factory=list)
    splits: Optional[Dict[str, List[str]]] = Field(
        default=None, description="Optional split partition mappings: {'train': [image_id, ...], 'val': [...]}"
    )
    contributor_id: Optional[str] = Field(
        default=None, description="Explicit contributor provenance when supplied (never inferred)"
    )
    batch_id: Optional[str] = Field(
        default=None, description="Batch identifier when supplied"
    )
    dataset_hash: str = Field(
        default="", description="Deterministic SHA-256 digest over sorted image digests and annotations"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)
    schema_version: str = Field(default="1.0")

    def compute_dataset_hash(self) -> str:
        """Compute deterministic SHA-256 hash over sorted images, annotations, classes, and metadata."""
        import hashlib

        sorted_images = sorted(
            [
                {
                    "path": img.file_path.replace("\\", "/"),
                    "hash": img.file_hash,
                    "width": img.width,
                    "height": img.height,
                }
                for img in self.images
            ],
            key=lambda x: x["path"],
        )
        sorted_annotations = sorted(
            [
                {
                    "image_id": a.image_id,
                    "class_id": a.class_id,
                    "bbox": [round(coord, 6) for coord in (a.bbox or [])],
                }
                for a in self.annotations
            ],
            key=lambda x: (x["image_id"], x["class_id"], str(x["bbox"])),
        )
        sorted_classes = sorted(
            [{"class_id": c.class_id, "name": c.class_name} for c in self.classes],
            key=lambda x: x["class_id"],
        )
        payload = {
            "format_origin": self.format_origin,
            "images": sorted_images,
            "annotations": sorted_annotations,
            "classes": sorted_classes,
            "contributor_id": self.contributor_id,
            "batch_id": self.batch_id,
            "schema_version": self.schema_version,
        }
        canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()


# =====================================================================
# Phase 4: Model Integrity & Reference Battery Schemas
# =====================================================================


class BatteryImage(CVIFBaseModel):
    """Individual test image within a reference battery."""

    image_id: str
    file_path: str = Field(..., description="Relative path from battery root using forward slashes")
    file_hash: str = Field(..., description="SHA-256 hex digest of image file")
    label: str = Field(..., description="Primary ground-truth class label or semantic description")
    difficulty: BatteryDifficulty = Field(default=BatteryDifficulty.MEDIUM)
    ground_truth_bboxes: Optional[List[DetectionOutput]] = Field(
        default=None, description="Expected bounding boxes for object detection verification"
    )
    perturbation_type: Optional[str] = Field(
        default=None, description="Synthetic trigger, noise, or patch type if perturbed"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ReferenceBattery(CVIFBaseModel):
    """Curated deterministic reference probe set for behavioral fingerprinting and testing."""

    battery_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    domain: str = Field(default="general_vision", description="Target domain, e.g., military_vehicle_detection")
    task_type: ModelTask
    images: List[BatteryImage] = Field(default_factory=list)
    expected_behaviors: Dict[str, Any] = Field(
        default_factory=dict, description="Expected outputs or tolerances for baseline reference model"
    )
    battery_hash: str = Field(default="", description="Deterministic SHA-256 digest over sorted battery images")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    schema_version: str = Field(default="1.0")

    def compute_battery_hash(self) -> str:
        """Compute deterministic SHA-256 digest over sorted images and battery parameters."""
        import hashlib

        sorted_images = sorted(
            [
                {
                    "image_id": img.image_id,
                    "path": img.file_path.replace("\\", "/"),
                    "hash": img.file_hash,
                    "label": img.label,
                    "difficulty": img.difficulty.value,
                    "perturbation": img.perturbation_type,
                }
                for img in self.images
            ],
            key=lambda x: x["image_id"],
        )
        payload = {
            "name": self.name,
            "domain": self.domain,
            "task_type": self.task_type.value,
            "images": sorted_images,
            "schema_version": self.schema_version,
        }
        canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()


class LayerInfo(CVIFBaseModel):
    """Structural information for an individual neural network layer or operator node."""

    name: str
    layer_type: str
    shape: List[int] = Field(default_factory=list)
    trainable: bool = True
    parameters_count: int = 0


class ArchitectureSummary(CVIFBaseModel):
    """High-level architectural summary of an inspected model."""

    total_parameters: int = 0
    trainable_parameters: int = 0
    non_trainable_parameters: int = 0
    layers: List[LayerInfo] = Field(default_factory=list)
    framework: str = Field(default="unknown")
    model_family: Optional[str] = None
    input_shape: Optional[List[int]] = None
    output_shape: Optional[List[int]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ParameterStats(CVIFBaseModel):
    """Statistical summary of weight/bias parameters in a model layer."""

    layer_name: str
    shape: List[int]
    total_elements: int
    mean: float
    std: float
    l2_norm: float
    min_val: float
    max_val: float
    sparsity_ratio: float = Field(default=0.0, description="Fraction of zero (or near-zero) values")


class ModelFingerprint(CVIFBaseModel):
    """Deterministic cryptographic and behavioral identity signature for a model."""

    model_id: str
    task_type: ModelTask
    artifact_hash: str = Field(..., description="SHA-256 of physical model file")
    weight_digest: str = Field(..., description="Deterministic SHA-256 over serialized weight tensors")
    architecture_hash: str = Field(..., description="SHA-256 of architecture metadata and layer names/shapes")
    behavioral_signature: List[float] = Field(
        default_factory=list, description="Fixed-dimensional behavioral output vector over reference battery"
    )
    probe_battery_hash: Optional[str] = Field(
        default=None, description="SHA-256 digest of probe battery used to compute behavioral signature"
    )
    task_specific_metrics: Dict[str, Any] = Field(default_factory=dict)
    schema_version: str = Field(default="1.0")


class ModelSafetyResult(CVIFBaseModel):
    """Outcome of pre-flight static model safety scan."""

    is_safe: bool
    detected_format: str
    file_size_bytes: int = 0
    file_hash: str = ""
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    security_metadata: Dict[str, Any] = Field(default_factory=dict)
