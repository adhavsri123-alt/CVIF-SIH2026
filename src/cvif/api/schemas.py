"""Pydantic request and response schemas for CVIF REST API (Phase 10)."""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from cvif.core.enums import (
    AssetType,
    Disposition,
    EvidenceType,
    ModelTask,
    ProvenanceOutcome,
    SeverityLevel,
)
from cvif.core.schemas import (
    AnalysisSession,
    AssuranceVerdict,
    EvidenceRecord,
    Finding,
    InferenceRecord,
)


# =====================================================================
# Generic & Error Schemas
# =====================================================================

class ErrorResponse(BaseModel):
    """Standardized machine-readable error envelope."""
    status: str = Field(default="ERROR")
    error_code: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


# =====================================================================
# System & Diagnostics Schemas
# =====================================================================

class AuditArchiveInfo(BaseModel):
    present: bool = False
    verified: bool = False
    archive_file: Optional[str] = None
    manifest_file: Optional[str] = None
    expected_sha256: Optional[str] = None
    actual_sha256: Optional[str] = None
    total_events: int = 0
    documented_discontinuities: int = 0
    error_message: Optional[str] = None


class AuditChainHealth(BaseModel):
    intact: bool
    broken_index: Optional[int] = None
    total_events: int
    verified_events: int
    log_file: str
    active_epoch: int = 1
    archive: Optional[AuditArchiveInfo] = None


class ServiceHealth(BaseModel):
    accessible: bool
    path: Optional[str] = None
    directory: Optional[str] = None


class HealthStatusResponse(BaseModel):
    status: str
    audit_chain: AuditChainHealth
    database: ServiceHealth
    evidence_store: ServiceHealth
    truststore: ServiceHealth


class VersionResponse(BaseModel):
    version: str
    schema_version: str
    architecture_version: str
    python_version: str
    platform: str
    air_gap_enforced: bool


# =====================================================================
# Audit Schemas
# =====================================================================

class AuditVerifyRequest(BaseModel):
    log_file: Optional[str] = Field(None, description="Optional path to custom audit.jsonl file.")


class AuditVerifyResponse(BaseModel):
    verified: bool
    broken_index: Optional[int] = None
    total_events: int
    verified_events: int
    error_message: Optional[str] = None
    log_file: str
    status: str
    active_epoch: int = 1
    archive: Optional[AuditArchiveInfo] = None


# =====================================================================
# Dataset Schemas
# =====================================================================

class DatasetIngestRequest(BaseModel):
    data_dir: str = Field(..., description="Path to dataset directory on server.")
    format: str = Field(default="auto", description="Dataset format: coco, yolo, or auto.")
    contributor_id: str = Field(default="local_contributor", description="Contributor organization identifier.")
    batch_id: Optional[str] = Field(None, description="Optional batch tracking identifier.")


class IngestValidationInfo(BaseModel):
    is_valid: bool
    warnings: List[str] = Field(default_factory=list)


class DatasetIngestResponse(BaseModel):
    status: str
    asset_id: UUID
    contributor_id: str
    format: str
    image_count: int
    annotation_count: int
    total_size_bytes: int
    validation: IngestValidationInfo


class DatasetScanRequest(BaseModel):
    data_dir: str = Field(..., description="Path to dataset directory on server.")
    session_id: Optional[UUID] = Field(None, description="Optional session UUID.")
    contributor_id: Optional[str] = Field(None, description="Contributor identifier.")


class DatasetScanResponse(BaseModel):
    session_id: UUID
    asset_id: UUID
    status: str
    findings_count: int
    has_critical_findings: bool
    findings: List[Finding]


# =====================================================================
# Model Schemas
# =====================================================================

class ModelSafetyScanRequest(BaseModel):
    model_path: str = Field(..., description="Path to model file on disk.")


class ModelSafetyScanResponse(BaseModel):
    model_path: str
    is_safe: bool
    detected_format: str
    file_hash: str
    file_size_bytes: int
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    status: str


class ModelScanRequest(BaseModel):
    model_path: str = Field(..., description="Path to candidate model weight file.")
    reference_weights: Optional[str] = Field(None, description="Optional path to golden reference weights.")
    session_id: Optional[UUID] = Field(None, description="Optional session UUID.")


class ModelScanResponse(BaseModel):
    session_id: UUID
    asset_id: UUID
    status: str
    total_findings: int
    has_critical_findings: bool
    executed_analyses: List[str] = Field(default_factory=list)
    findings: List[Finding]


# =====================================================================
# Provenance Schemas
# =====================================================================

class ProvenanceVerifyRequest(BaseModel):
    record: InferenceRecord = Field(..., description="Inference record with cryptographic binding.")
    raw_image_path: Optional[str] = Field(None, description="Optional path to raw image file for digest matching.")
    expected_model_digest: Optional[str] = Field(None, description="Optional expected model weight SHA-256 digest.")
    tolerance_seconds: Optional[float] = Field(None, description="Allowable timestamp skew tolerance in seconds (defaults to 86400.0).")
    enforce_replay_checks: Optional[bool] = Field(True, description="Whether to enforce replay protection checks.")

    @model_validator(mode="before")
    @classmethod
    def allow_direct_record(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # If user posted the InferenceRecord directly at root
            if "record" not in data and ("input_image_hash" in data or "model_weight_digest" in data or "output" in data):
                return {
                    "record": data,
                    "raw_image_path": None,
                    "expected_model_digest": None,
                    "tolerance_seconds": None,
                    "enforce_replay_checks": True,
                }
        return data


class ProvenanceVerifyResponse(BaseModel):
    record_id: UUID
    session_id: UUID
    contributor_id: str
    status: str
    is_valid: bool
    findings_count: int
    findings: List[Finding]
    details: Dict[str, Any] = Field(default_factory=dict)


class ProvenanceDemoRecordRequest(BaseModel):
    session_id: Optional[UUID] = Field(None, description="Optional session UUID to associate/continue sequence for.")
    new_session: bool = Field(False, description="If True, generate with a fresh session UUID.")
    tampered: bool = Field(False, description="If True, generate a tampered record for demo.")


class ProvenanceDemoRecordResponse(BaseModel):
    record: InferenceRecord
    sequence_number: int
    is_tampered: bool
    message: str


# =====================================================================
# Distribution Shift Schemas
# =====================================================================

class DistributionShiftRequest(BaseModel):
    reference_data: str = Field(..., description="Path to golden baseline reference dataset.")
    evaluation_data: str = Field(..., description="Path to operational evaluation dataset.")
    session_id: Optional[UUID] = Field(None, description="Optional session UUID.")


class DimensionShiftInfo(BaseModel):
    dimension_name: str
    shift_detected: bool
    p_value: Optional[float] = None
    statistic_value: float
    threshold: float
    details: Dict[str, Any] = Field(default_factory=dict)


class DistributionShiftResponse(BaseModel):
    session_id: UUID
    reference_asset_id: UUID
    evaluation_asset_id: UUID
    overall_shift_detected: bool
    dimensions: Dict[str, DimensionShiftInfo]
    findings_count: int
    findings: List[Finding]
    overall_distance: Optional[float] = None
    natural_drift_likelihood: Optional[float] = None
    suspicious_manipulation_likelihood: Optional[float] = None
    characterization: Optional[str] = None


# =====================================================================
# Assurance Schemas
# =====================================================================

class AssessRequest(BaseModel):
    session_id: UUID = Field(..., description="Analysis session UUID to synthesize verdict for.")


# =====================================================================
# Evidence Schemas
# =====================================================================

class EvidenceRecordSummary(BaseModel):
    evidence_id: UUID
    session_id: UUID
    finding_id: Optional[UUID] = None
    evidence_type: str
    content_hash: str
    created_at: str
    threat_id: Optional[str] = None


class EvidenceListResponse(BaseModel):
    total: int
    records: List[EvidenceRecordSummary]


class EvidenceVerifyRequest(BaseModel):
    session_id: Optional[UUID] = Field(None, description="Optionally filter consistency check to specific session.")


class EvidenceConsistencyResponse(BaseModel):
    total_records: int
    total_artifacts: int
    is_consistent: bool
    missing_records: List[str] = Field(default_factory=list)
    tampered_records: List[str] = Field(default_factory=list)
    missing_artifacts: List[str] = Field(default_factory=list)
    tampered_artifacts: List[str] = Field(default_factory=list)
    orphan_evidence: List[str] = Field(default_factory=list)
    orphan_artifacts: List[str] = Field(default_factory=list)



class EvidenceExportRequest(BaseModel):
    session_id: UUID = Field(..., description="Session UUID to package.")
    output_path: Optional[str] = Field(None, description="Optional target archive path.")


class EvidenceExportResponse(BaseModel):
    session_id: UUID
    archive_path: str
    total_records: int
    total_files: int
    sha256_manifest_digest: str
