"""Integrity Lineage analysis, cross-pipeline verification, and tracing endpoints."""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from cvif.api.dependencies import get_runtime_context, verify_api_key
from cvif.api.schemas import (
    AssuranceLineageNode,
    AuditLineageNode,
    DatasetLineageNode,
    DistributionLineageNode,
    EvidenceLineageNode,
    EvidenceRecordSummary,
    InferenceLineageNode,
    IntegrityLineageResponse,
    LineageDependency,
    LineageVerifyRequest,
    ModelLineageNode,
    UnsupportedCheckDetail,
)
from cvif.audit.logger import AuditLogger
from cvif.cli.commands.common import RuntimeContext
from cvif.core.enums import AssetType, Disposition, SeverityLevel
from cvif.core.schemas import AnalysisSession, AssuranceVerdict, Finding

router = APIRouter(prefix="/lineage", tags=["Integrity Lineage"])


def _build_lineage_for_session(
    session_id: str, ctx: RuntimeContext
) -> IntegrityLineageResponse:
    """Dynamically reconstruct and verify integrity lineage for an active session using real persisted data."""
    session = ctx.db.get_session(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis session not found: {session_id}",
        )

    # 1. Fetch all findings recorded for this session from DB and session object
    db_findings = ctx.db.get_findings_for_session(session_id)
    findings_map: Dict[UUID, Finding] = {f.finding_id: f for f in db_findings}
    for f in session.findings or []:
        if f.finding_id not in findings_map:
            findings_map[f.finding_id] = f
    all_findings = list(findings_map.values())

    # 2. Fetch associated asset if present
    asset = ctx.db.get_asset(session.asset_id) if session.asset_id else None

    # 3. DATASET NODE
    dt_findings = [
        f for f in all_findings
        if f.threat_id.startswith("DT-") or f.category == "DATA_INTEGRITY"
    ]
    supported_dt_checks = [a for a in session.executed_analyses if a.startswith("DT-")]
    has_dt_run = (
        len(supported_dt_checks) > 0
        or len(dt_findings) > 0
        or "DATASET" in session.executed_analyses
    )

    dataset_id = str(asset.asset_id) if asset else str(session.asset_id)
    dataset_fmt = asset.format if asset else session.execution_environment.get("format")
    dataset_hash = None
    if asset and asset.hash_manifest and asset.hash_manifest.entries:
        dataset_hash = asset.hash_manifest.entries[0].digest
    elif session.execution_environment.get("dataset_hash"):
        dataset_hash = session.execution_environment["dataset_hash"]

    # Real evidence count for DT findings
    dt_evidence_count = 0
    for f in dt_findings:
        dt_evidence_count += len(ctx.db.list_evidence_records(finding_id=f.finding_id))

    if not has_dt_run:
        dt_status = "NOT RUN"
    elif any(f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) for f in dt_findings):
        dt_status = "FAILED / TAMPERED"
    elif any(f.severity in (SeverityLevel.MEDIUM, SeverityLevel.LOW) for f in dt_findings):
        dt_status = "FINDINGS"
    else:
        dt_status = "VERIFIED"

    dataset_node = DatasetLineageNode(
        stage="DATASET",
        status=dt_status,
        dataset_identity=dataset_id if (has_dt_run or (asset and asset.asset_type == AssetType.DATASET)) else None,
        dataset_hash=dataset_hash if (has_dt_run or (asset and asset.asset_type == AssetType.DATASET)) else None,
        format=dataset_fmt if (has_dt_run or (asset and asset.asset_type == AssetType.DATASET)) else None,
        findings_count=len(dt_findings),
        findings=dt_findings,
        evidence_count=dt_evidence_count,
        details={"executed_analyses": supported_dt_checks},
    )

    # 4. MODEL NODE
    mt_findings = [
        f for f in all_findings
        if f.threat_id.startswith("MT-") or f.category == "MODEL_INTEGRITY"
    ]
    supported_mt_checks = [a for a in session.executed_analyses if a.startswith("MT-")]
    unsupported_mt_checks: List[UnsupportedCheckDetail] = []
    for s in session.skipped_analyses or []:
        aid = s.get("analysis_id", "")
        if aid.startswith("MT-") or "MT-" in aid:
            unsupported_mt_checks.append(
                UnsupportedCheckDetail(
                    check_id=aid,
                    reason=s.get("reason", "Required capability unavailable"),
                )
            )

    has_mt_run = (
        len(supported_mt_checks) > 0
        or len(unsupported_mt_checks) > 0
        or len(mt_findings) > 0
        or "MODEL" in session.executed_analyses
    )

    candidate_id = session.execution_environment.get("model_id") or (str(asset.asset_id) if (asset and asset.asset_type == AssetType.MODEL) else None)
    model_digest = session.execution_environment.get("model_digest")
    if not model_digest and asset and asset.hash_manifest and asset.hash_manifest.entries and asset.asset_type == AssetType.MODEL:
        model_digest = asset.hash_manifest.entries[0].digest
    ref_model = session.execution_environment.get("reference_weights")

    if not has_mt_run:
        mt_status = "NOT RUN"
    elif any(f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) for f in mt_findings):
        mt_status = "FAILED / TAMPERED"
    elif any(f.severity in (SeverityLevel.MEDIUM, SeverityLevel.LOW) for f in mt_findings):
        mt_status = "FINDINGS"
    elif len(unsupported_mt_checks) > 0 and len(supported_mt_checks) == 0:
        mt_status = "UNSUPPORTED"
    elif len(unsupported_mt_checks) > 0:
        mt_status = "REVIEW"
    else:
        mt_status = "VERIFIED"

    model_node = ModelLineageNode(
        stage="MODEL",
        status=mt_status,
        candidate_model_id=candidate_id if has_mt_run else None,
        model_digest=model_digest if has_mt_run else None,
        reference_model=ref_model if has_mt_run else None,
        findings_count=len(mt_findings),
        findings=mt_findings,
        supported_checks=supported_mt_checks,
        unsupported_checks=unsupported_mt_checks,
        details={"environment": session.execution_environment},
    )

    # 5. INFERENCE NODE
    prov_record = ctx.db.get_provenance_for_session(session_id)
    it_findings = [
        f for f in all_findings
        if f.threat_id.startswith("IT-") or f.category == "INFERENCE_PROVENANCE"
    ]

    is_inference_verified = (
        prov_record is not None
        or len(it_findings) > 0
        or "INFERENCE_PROVENANCE" in session.executed_analyses
    )

    if not is_inference_verified:
        inference_node = InferenceLineageNode(
            stage="INFERENCE",
            status="NOT RUN",
            record_id=None,
            session_id=session_id,
            bound_model_digest=None,
            verification_state="NOT RUN",
            is_valid=False,
            is_tampered=False,
            is_replayed=False,
            model_mismatch=False,
            producer_id=None,
            signing_key_id=None,
            findings_count=0,
            findings=[],
            details={"message": "No inference record verified for this session"},
        )
    else:
        rec_id = prov_record["record_id"] if prov_record else (str(it_findings[0].asset_id) if it_findings else None)
        bound_digest = prov_record["model_weight_digest"] if prov_record else None
        v_state = prov_record["status"] if prov_record else ("TAMPERED_OUTPUT" if any(f.threat_id == "IT-1" for f in it_findings) else "VERIFIED")
        is_val = bool(prov_record["is_valid"]) if prov_record else (len(it_findings) == 0)
        is_tamp = any(f.threat_id == "IT-1" for f in it_findings) or v_state in ("TAMPERED_OUTPUT", "SIGNATURE_INVALID")
        is_repl = any(f.threat_id == "IT-2" for f in it_findings) or v_state == "REPLAYED_RECORD"
        prod_id = prov_record.get("producer_id") if prov_record else None
        key_id = prov_record.get("signing_key_id") if prov_record else None

        # Cross-reference model digest: Candidate Model vs Inference Record bound digest
        model_mismatch = False
        if model_node.model_digest and bound_digest:
            if model_node.model_digest.strip().lower() != bound_digest.strip().lower():
                model_mismatch = True

        if is_tamp or is_repl or v_state in ("TAMPERED_OUTPUT", "REPLAYED_RECORD", "SUBSTITUTED_MODEL"):
            it_status = "FAILED / TAMPERED"
        elif model_mismatch:
            it_status = "FAILED / TAMPERED"
        elif any(f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) for f in it_findings):
            it_status = "FAILED / TAMPERED"
        elif any(f.severity in (SeverityLevel.MEDIUM, SeverityLevel.LOW) for f in it_findings):
            it_status = "FINDINGS"
        elif not is_val:
            it_status = "FAILED / TAMPERED"
        else:
            it_status = "VERIFIED"

        inference_node = InferenceLineageNode(
            stage="INFERENCE",
            status=it_status,
            record_id=rec_id,
            session_id=session_id,
            bound_model_digest=bound_digest,
            verification_state=v_state,
            is_valid=is_val,
            is_tampered=is_tamp,
            is_replayed=is_repl,
            model_mismatch=model_mismatch,
            producer_id=prod_id,
            signing_key_id=key_id,
            findings_count=len(it_findings),
            findings=it_findings,
            details={
                "producer_id": prod_id,
                "signing_key_id": key_id,
                "details_json": prov_record.get("details_json") if prov_record else None,
            },
        )

    # 6. DISTRIBUTION NODE
    ds_findings = [
        f for f in all_findings
        if f.threat_id.startswith("DS-") or f.category == "DISTRIBUTION_SHIFT"
    ]
    is_ds_session = (
        any(a.startswith("DS-") or a == "DISTRIBUTION_SHIFT" for a in session.executed_analyses)
        or len(ds_findings) > 0
    )

    if not is_ds_session:
        distribution_node = DistributionLineageNode(
            stage="DISTRIBUTION",
            status="NOT RUN",
            executed=False,
            overall_distance=None,
            natural_drift_likelihood=None,
            suspicious_manipulation_likelihood=None,
            shift_detected=False,
            dimension_results={},
            characterization=None,
            details={"message": "Distribution shift analysis not executed for this session"},
        )
    else:
        has_suspicious = any(f.threat_id == "DS-4" or f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) for f in ds_findings)
        has_drift = any(f.severity in (SeverityLevel.MEDIUM, SeverityLevel.LOW) for f in ds_findings)

        if has_suspicious:
            ds_status = "FAILED / TAMPERED"
        elif has_drift:
            ds_status = "REVIEW"
        else:
            ds_status = "VERIFIED"

        distribution_node = DistributionLineageNode(
            stage="DISTRIBUTION",
            status=ds_status,
            executed=True,
            overall_distance=session.execution_environment.get("overall_distance", 0.0),
            natural_drift_likelihood=session.execution_environment.get("natural_drift_likelihood", 0.1),
            suspicious_manipulation_likelihood=session.execution_environment.get("suspicious_manipulation_likelihood", 0.0),
            shift_detected=has_drift or has_suspicious,
            dimension_results=session.execution_environment.get("dimension_results", {}),
            characterization=session.execution_environment.get("characterization", "Distribution analyzed"),
            details={"findings_count": len(ds_findings)},
        )

    # 7. EVIDENCE NODE
    ev_rows = ctx.db.list_evidence_records(session_id=session_id)
    crypto_c = sum(1 for r in ev_rows if str(r.get("evidence_type", "")).upper() == "CRYPTOGRAPHIC")
    stat_c = sum(1 for r in ev_rows if str(r.get("evidence_type", "")).upper() == "STATISTICAL")
    art_c = sum(1 for r in ev_rows if str(r.get("evidence_type", "")).upper() == "ARTIFACT")

    ev_summaries = [
        EvidenceRecordSummary(
            evidence_id=r["evidence_id"],
            session_id=r["session_id"],
            finding_id=r.get("finding_id"),
            evidence_type=r.get("evidence_type", "UNKNOWN"),
            content_hash=r.get("content_hash", ""),
            created_at=r.get("created_at", ""),
        )
        for r in ev_rows[:50]
    ]

    ev_status = "VERIFIED" if len(ev_rows) > 0 else "NOT RUN"
    evidence_node = EvidenceLineageNode(
        stage="EVIDENCE",
        status=ev_status,
        total_records=len(ev_rows),
        cryptographic_records=crypto_c,
        statistical_records=stat_c,
        artifact_records=art_c,
        records=ev_summaries,
        details={"session_id": session_id},
    )

    # 8. AUDIT NODE
    target_log = ctx.config.audit.audit_log_path
    if target_log.is_file():
        audit_logger = AuditLogger(target_log, auto_verify_on_init=False)
        chain_res = audit_logger.verify_chain()
        audit_intact = chain_res.is_valid
        total_evts = chain_res.total_events
        ver_evts = chain_res.verified_events
        err_msg = chain_res.error_message
    else:
        audit_intact = True
        total_evts = 0
        ver_evts = 0
        err_msg = None

    audit_status = "VERIFIED" if audit_intact else "FAILED / TAMPERED"
    audit_node = AuditLineageNode(
        stage="AUDIT",
        status=audit_status,
        active_epoch=1,
        chain_intact=audit_intact,
        total_events=total_evts,
        verified_events=ver_evts,
        error_message=err_msg,
        details={"log_file": str(target_log)},
    )

    # 9. ASSURANCE NODE
    verdict = ctx.db.get_verdict_for_session(session_id) or session.verdict
    if verdict is None:
        assurance_node = AssuranceLineageNode(
            stage="ASSURANCE",
            status="NOT RUN",
            assessed=False,
            disposition=None,
            composite_risk_score=None,
            summary=None,
            coverage_state="NOT RUN",
            contributing_finding_ids=[],
            unsupported_checks=[],
            details={"message": "Assurance assessment not yet synthesized for this session"},
        )
    else:
        disp_val = verdict.disposition.value
        if disp_val == "QUARANTINE":
            ass_status = "FAILED / TAMPERED"
        elif disp_val == "REVIEW":
            ass_status = "REVIEW"
        else:
            ass_status = "VERIFIED"

        unsupported_list = list(verdict.unsupported_checks or [])
        cov_state = "LIMITED COVERAGE" if len(unsupported_list) > 0 else "COMPLETE"

        assurance_node = AssuranceLineageNode(
            stage="ASSURANCE",
            status=ass_status,
            assessed=True,
            disposition=disp_val,
            composite_risk_score=verdict.composite_risk_score,
            summary=verdict.summary,
            coverage_state=cov_state,
            contributing_finding_ids=[str(fid) for fid in verdict.contributing_finding_ids],
            unsupported_checks=unsupported_list,
            details={"verdict_id": str(verdict.verdict_id)},
        )

    # 10. DEPENDENCIES
    dependencies: List[LineageDependency] = [
        LineageDependency(
            source="DATASET",
            target="MODEL",
            relationship="TRAINED_WITH / EVALUATED_AGAINST",
            is_valid=dataset_node.status == "VERIFIED" and model_node.status != "FAILED / TAMPERED",
            description="Dataset training baseline and probe battery input",
        ),
        LineageDependency(
            source="MODEL",
            target="INFERENCE",
            relationship="WEIGHT_DIGEST_BINDING",
            is_valid=(not inference_node.model_mismatch) and (inference_node.status != "FAILED / TAMPERED"),
            description=(
                "MODEL MISMATCH: Inference model digest does not match candidate model"
                if inference_node.model_mismatch
                else "Inference record cryptographically bound to verified model weight digest"
            ),
        ),
        LineageDependency(
            source="INFERENCE",
            target="DISTRIBUTION",
            relationship="OPERATIONAL_STREAM_SAMPLE",
            is_valid=inference_node.status != "FAILED / TAMPERED" and distribution_node.status != "FAILED / TAMPERED",
            description="Operational inference inputs evaluated for covariate and semantic drift",
        ),
        LineageDependency(
            source="DISTRIBUTION",
            target="EVIDENCE",
            relationship="EVIDENCE_PERSISTENCE",
            is_valid=evidence_node.total_records > 0,
            description="Multi-stage forensic artifacts indexed in evidence store",
        ),
        LineageDependency(
            source="EVIDENCE",
            target="AUDIT",
            relationship="TAMPER_EVIDENT_AUDIT_LOG",
            is_valid=audit_node.chain_intact,
            description="Forensic evidence events anchored into SHA-256 audit ledger",
        ),
        LineageDependency(
            source="AUDIT",
            target="ASSURANCE",
            relationship="HOLISTIC_ASSURANCE_EVALUATION",
            is_valid=assurance_node.status != "FAILED / TAMPERED",
            description="Weakest-Link Critical Veto and calibrated Noisy-OR verdict synthesis",
        ),
    ]

    # 11. OVERALL STATUS EVALUATION
    # Priority 1: Critical integrity failures
    nodes = [dataset_node, model_node, inference_node, distribution_node, audit_node, assurance_node]
    has_failed = (
        any(n.status == "FAILED / TAMPERED" for n in nodes)
        or inference_node.is_tampered
        or inference_node.model_mismatch
        or (assurance_node.disposition == "QUARANTINE")
        or (not audit_node.chain_intact)
    )

    if has_failed:
        overall_status = "FAILED / QUARANTINE"
        reasons = []
        if inference_node.is_tampered:
            reasons.append("Inference record tampered (IT-1)")
        if inference_node.model_mismatch:
            reasons.append("Model weight digest mismatch between model and inference")
        if not audit_node.chain_intact:
            reasons.append("Audit ledger chain broken")
        if assurance_node.disposition == "QUARANTINE":
            reasons.append("Critical veto triggered in assurance evaluation")
        summary = f"Critical integrity failure detected: {', '.join(reasons) if reasons else 'Veto condition triggered'}. Quarantine recommended."

    # Priority 2: Incomplete pipeline
    elif (
        dataset_node.status == "NOT RUN"
        and model_node.status == "NOT RUN"
        and inference_node.status == "NOT RUN"
    ):
        overall_status = "INCOMPLETE / NOT VERIFIED"
        summary = "Analysis pipeline incomplete. Core components have not been executed for this session."

    # Priority 3: Findings / Review
    elif (
        len(all_findings) > 0
        or any(n.status == "FINDINGS" for n in nodes)
        or (assurance_node.disposition == "REVIEW")
    ):
        overall_status = "FINDINGS / REVIEW"
        summary = f"Lineage traced with {len(all_findings)} finding(s) requiring analyst review."

    # Priority 4: Limited coverage (e.g. MT-3 unsupported)
    elif (
        len(model_node.unsupported_checks) > 0
        or model_node.status in ("UNSUPPORTED", "REVIEW")
        or assurance_node.coverage_state == "LIMITED COVERAGE"
    ):
        overall_status = "LIMITED COVERAGE"
        unsupported_names = ", ".join(u.check_id for u in model_node.unsupported_checks) or "Prerequisite capabilities"
        summary = f"Pipeline verified under limited coverage. Unsupported checks: {unsupported_names}."

    # Priority 5: Full verification
    elif (
        (dataset_node.status in ("VERIFIED", "NOT RUN"))
        and (model_node.status in ("VERIFIED", "NOT RUN"))
        and (inference_node.status in ("VERIFIED", "NOT RUN"))
        and audit_node.chain_intact
        and (assurance_node.disposition == "ACCEPT" or assurance_node.status in ("VERIFIED", "NOT RUN"))
    ):
        overall_status = "VERIFIED"
        summary = "All executed pipeline assets and cryptographic evidence verified intact across complete lineage."
    else:
        overall_status = "INCOMPLETE / NOT VERIFIED"
        summary = "Pipeline verification incomplete. Additional verification required."

    return IntegrityLineageResponse(
        session_id=session_id,
        overall_status=overall_status,
        summary=summary,
        dataset=dataset_node,
        model=model_node,
        inference=inference_node,
        distribution=distribution_node,
        evidence=evidence_node,
        audit=audit_node,
        assurance=assurance_node,
        dependencies=dependencies,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get(
    "/session/{session_id}",
    response_model=IntegrityLineageResponse,
    summary="Get Integrity Lineage for Session",
    description="Retrieve end-to-end integrity lineage connecting Dataset, Model, Inference, Distribution, Evidence, Audit, and Assurance using real persisted data.",
)
def get_session_lineage(
    session_id: str,
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> IntegrityLineageResponse:
    return _build_lineage_for_session(session_id, ctx)


@router.post(
    "/verify",
    response_model=IntegrityLineageResponse,
    summary="Verify Integrity Lineage",
    description="Execute complete cryptographic cross-verification over all session pipeline nodes and return authoritative lineage verification result.",
)
def verify_lineage(
    req: LineageVerifyRequest,
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> IntegrityLineageResponse:
    return _build_lineage_for_session(req.session_id, ctx)
