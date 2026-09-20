"""Distribution shift analysis endpoints."""

from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, status

from cvif.analysis.distribution_shift.orchestrator import DistributionShiftOrchestrator
from cvif.api.dependencies import get_runtime_context, resolve_api_path, verify_api_key
from cvif.api.schemas import (
    DimensionShiftInfo,
    DistributionShiftRequest,
    DistributionShiftResponse,
)
from cvif.cli.commands.common import RuntimeContext
from cvif.features.statistical import StatisticalFeatureExtractor
from cvif.ingestion.gateway import IngestionGateway

router = APIRouter(prefix="/shift", tags=["Distribution Shift"])


@router.post(
    "/analyze",
    response_model=DistributionShiftResponse,
    summary="Analyze Distribution Shift (DS-1 to DS-4)",
    description="Compare baseline reference dataset with operational evaluation dataset across covariate and semantic shift dimensions.",
)
def analyze_distribution_shift(
    req: DistributionShiftRequest,
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> DistributionShiftResponse:
    ref_path = resolve_api_path(req.reference_data, must_exist=True)
    eval_path = resolve_api_path(req.evaluation_data, must_exist=True)

    gateway = IngestionGateway(audit_logger=ctx.audit, db_manager=ctx.db)
    ref_unified, _, _ = gateway.ingest_dataset(ref_path, contributor_id="reference")
    eval_unified, _, _ = gateway.ingest_dataset(eval_path, contributor_id="evaluation")

    feature_extractor = StatisticalFeatureExtractor()
    orchestrator = DistributionShiftOrchestrator(
        feature_extractor=feature_extractor,
        evidence_store=ctx.evidence,
        audit_logger=ctx.audit,
        db_manager=ctx.db,
    )

    sess_uuid = req.session_id or uuid4()
    report, session = orchestrator.run_analysis(
        reference_dataset=ref_unified,
        evaluation_dataset=eval_unified,
        session_id=sess_uuid,
        operator_id="cvif_api",
    )

    default_thresholds = {
        "covariate_shift": 0.15,
        "semantic_shift": 0.25,
        "environmental_drift": 0.20,
        "adversarial_manipulation": 0.25,
    }

    dim_info_map = {
        dim_name: DimensionShiftInfo(
            dimension_name=dim_name,
            shift_detected=res.detected,
            p_value=res.p_value,
            statistic_value=res.metric_value,
            threshold=default_thresholds.get(dim_name, 0.20),
            details={"description": res.description},
        )
        for dim_name, res in report.dimensions.items()
    }

    overall_shift = any(res.detected for res in report.dimensions.values())

    return DistributionShiftResponse(
        session_id=report.session_id,
        reference_asset_id=report.reference_asset_id,
        evaluation_asset_id=report.evaluation_asset_id,
        overall_shift_detected=overall_shift,
        dimensions=dim_info_map,
        findings_count=len(session.findings or []),
        findings=session.findings or [],
        overall_distance=report.overall_distance,
        natural_drift_likelihood=report.assessment.natural_drift_likelihood if report.assessment else None,
        suspicious_manipulation_likelihood=report.assessment.suspicious_manipulation_likelihood if report.assessment else None,
        characterization=report.characterization,
    )
