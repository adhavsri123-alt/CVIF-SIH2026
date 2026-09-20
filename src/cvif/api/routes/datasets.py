"""Dataset ingestion and integrity scanning endpoints."""

from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, status

from cvif.analysis.orchestrator import DatasetIntegrityOrchestrator
from cvif.api.dependencies import get_runtime_context, resolve_api_path, verify_api_key
from cvif.api.schemas import (
    DatasetIngestRequest,
    DatasetIngestResponse,
    DatasetScanRequest,
    DatasetScanResponse,
    IngestValidationInfo,
)
from cvif.cli.commands.common import RuntimeContext
from cvif.core.enums import SeverityLevel
from cvif.features.statistical import StatisticalFeatureExtractor
from cvif.ingestion.gateway import IngestionGateway

router = APIRouter(prefix="/datasets", tags=["Dataset Integrity"])


@router.post(
    "/ingest",
    response_model=DatasetIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest and Catalog Dataset",
    description="Validate dataset structure (COCO/YOLO), compute perceptual dhashes, and register asset.",
)
def ingest_dataset(
    req: DatasetIngestRequest,
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> DatasetIngestResponse:
    resolved_path = resolve_api_path(req.data_dir, must_exist=True)
    gateway = IngestionGateway(audit_logger=ctx.audit, db_manager=ctx.db)

    unified, val_res, asset_reg = gateway.ingest_dataset(
        dataset_path=resolved_path,
        contributor_id=req.contributor_id,
        batch_id=req.batch_id,
        compute_hashes=True,
    )

    return DatasetIngestResponse(
        status="INGESTED",
        asset_id=asset_reg.asset_id,
        contributor_id=asset_reg.contributor_id,
        format=asset_reg.format,
        image_count=len(unified.images),
        annotation_count=len(unified.annotations),
        total_size_bytes=asset_reg.total_size_bytes,
        validation=IngestValidationInfo(
            is_valid=val_res.is_valid,
            warnings=val_res.warnings,
        ),
    )


@router.post(
    "/scan",
    response_model=DatasetScanResponse,
    summary="Scan Dataset Integrity (DT-1 to DT-6)",
    description="Execute the complete training data integrity analysis battery against an ingested dataset.",
)
def scan_dataset(
    req: DatasetScanRequest,
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> DatasetScanResponse:
    resolved_path = resolve_api_path(req.data_dir, must_exist=True)
    gateway = IngestionGateway(audit_logger=ctx.audit, db_manager=ctx.db)

    unified, _, asset_reg = gateway.ingest_dataset(
        dataset_path=resolved_path,
        contributor_id=req.contributor_id or "analyst",
        compute_hashes=True,
    )

    sess_uuid = req.session_id or uuid4()
    feature_extractor = StatisticalFeatureExtractor()
    orchestrator = DatasetIntegrityOrchestrator(
        feature_extractor=feature_extractor,
        evidence_store=ctx.evidence,
        audit_logger=ctx.audit,
        db_manager=ctx.db,
    )

    session = orchestrator.run_analysis(
        dataset=unified,
        session_id=sess_uuid,
        operator_id="cvif_api",
    )

    findings = session.findings or []
    has_severe = any(
        f.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
        for f in findings
    )

    return DatasetScanResponse(
        session_id=session.session_id,
        asset_id=session.asset_id,
        status=session.status.value,
        findings_count=len(findings),
        has_critical_findings=has_severe,
        findings=findings,
    )
