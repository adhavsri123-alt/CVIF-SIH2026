"""Model safety and integrity analysis endpoints."""

from pathlib import Path
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, status

from cvif.analysis.model_orchestrator import ModelIntegrityOrchestrator
from cvif.api.dependencies import get_runtime_context, resolve_api_path, verify_api_key
from cvif.api.schemas import (
    ModelSafetyScanRequest,
    ModelSafetyScanResponse,
    ModelScanRequest,
    ModelScanResponse,
)
from cvif.cli.commands.common import RuntimeContext
from cvif.core.enums import ModelTask, SeverityLevel
from cvif.core.exceptions import InvalidModelError
from cvif.model.adapter import MockModelAdapter, ModelAdapter
from cvif.model.adapters import ONNXAdapter, PyTorchAdapter, TorchScriptAdapter
from cvif.model.battery import ReferenceBatteryBuilder
from cvif.model.safety import scan_model_file, validate_model_file_safety

router = APIRouter(prefix="/models", tags=["Model Safety & Integrity"])


def _resolve_model_adapter(model_path: Path) -> ModelAdapter:
    """Select and instantiate appropriate model adapter based on file extension."""
    suffix = model_path.suffix.lower()
    if suffix == ".onnx":
        return ONNXAdapter(model_path)
    if suffix in (".pt", ".pth"):
        try:
            return TorchScriptAdapter(model_path)
        except Exception:
            return PyTorchAdapter(model_path)
    if suffix == ".torchscript":
        return TorchScriptAdapter(model_path)
    # Fallback to mock adapter for testing or generic weights
    adapter = MockModelAdapter(task=ModelTask.CLASSIFICATION)
    adapter.model_path = model_path
    return adapter


@router.post(
    "/scan-safety",
    response_model=ModelSafetyScanResponse,
    summary="Pre-Flight Model File Safety Scan",
    description="Scan raw model file for pickle deserialization exploits, zip bombs, and corrupt headers.",
)
def scan_model_safety(
    req: ModelSafetyScanRequest,
    _: None = Depends(verify_api_key),
) -> ModelSafetyScanResponse:
    resolved_path = resolve_api_path(req.model_path, must_exist=True)

    try:
        safety_result = scan_model_file(resolved_path)
        is_safe = safety_result.is_safe
        detected_format = safety_result.detected_format
        file_hash = safety_result.file_hash
        file_size_bytes = safety_result.file_size_bytes
        errors = safety_result.errors
        warnings = safety_result.warnings
    except InvalidModelError as err:
        is_safe = False
        detected_format = "unknown"
        file_hash = ""
        file_size_bytes = resolved_path.stat().st_size if resolved_path.is_file() else 0
        errors = [str(err)]
        warnings = []

    return ModelSafetyScanResponse(
        model_path=str(resolved_path),
        is_safe=is_safe,
        detected_format=detected_format,
        file_hash=file_hash,
        file_size_bytes=file_size_bytes,
        errors=errors,
        warnings=warnings,
        status="PASSED" if is_safe else "UNSAFE_MODEL_DETECTED",
    )


@router.post(
    "/scan",
    response_model=ModelScanResponse,
    summary="Execute Model Integrity Battery (MT-1 to MT-4)",
    description="Run behavioral test battery against candidate model, enforcing pre-flight safety scan before weight loading.",
)
def scan_model(
    req: ModelScanRequest,
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> ModelScanResponse:
    resolved_model = resolve_api_path(req.model_path, must_exist=True)

    # 1. ENFORCE PRE-FLIGHT SAFETY SCAN BEFORE LOADING WEIGHTS
    validate_model_file_safety(resolved_model)

    candidate_adapter = _resolve_model_adapter(resolved_model)
    reference_adapter: Optional[ModelAdapter] = None
    if req.reference_weights:
        resolved_ref = resolve_api_path(req.reference_weights, must_exist=True)
        validate_model_file_safety(resolved_ref)
        reference_adapter = _resolve_model_adapter(resolved_ref)

    battery = ReferenceBatteryBuilder.create_synthetic_battery(
        task_type=candidate_adapter.get_task_type(),
    )

    orchestrator = ModelIntegrityOrchestrator(
        evidence_store=ctx.evidence,
        audit_logger=ctx.audit,
        db_manager=ctx.db,
    )

    sess_uuid = req.session_id or uuid4()
    session = orchestrator.run_analysis(
        candidate_model=candidate_adapter,
        reference_model=reference_adapter,
        battery=battery,
        session_id=sess_uuid,
        operator_id="cvif_api",
    )

    findings = session.findings or []
    has_severe = any(
        f.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
        for f in findings
    )

    return ModelScanResponse(
        session_id=session.session_id,
        asset_id=session.asset_id,
        status=session.status.value,
        total_findings=len(findings),
        has_critical_findings=has_severe,
        executed_analyses=session.executed_analyses,
        findings=findings,
    )
