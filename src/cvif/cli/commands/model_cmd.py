"""Model safety scanning and model integrity analysis commands for CVIF CLI."""

from pathlib import Path
import sys
from typing import Optional
from uuid import UUID, uuid4

import typer

from cvif.analysis.model_orchestrator import ModelIntegrityOrchestrator
from cvif.cli.commands.common import get_runtime_context, resolve_cli_path
from cvif.cli.error_handler import cli_error_boundary
from cvif.cli.exit_codes import (
    EXIT_CLI_ERROR,
    EXIT_MODEL_INTEGRITY_FINDING,
    EXIT_SUCCESS,
)
from cvif.cli.output import emit_result
from cvif.core.enums import ModelTask, SeverityLevel
from cvif.core.exceptions import InvalidModelError
from cvif.model.adapter import MockModelAdapter, ModelAdapter
from cvif.model.adapters import ONNXAdapter, PyTorchAdapter, TorchScriptAdapter
from cvif.model.battery import ReferenceBatteryBuilder
from cvif.model.safety import scan_model_file, validate_model_file_safety

model_app = typer.Typer(help="Scan model safety and run model integrity analysis (MT-1 to MT-4).")


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


@model_app.command("scan-safety")
@cli_error_boundary
def model_scan_safety(
    model_path: Path = typer.Option(
        ..., "--model-path", "-m", help="Path to raw model weight file on disk."
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to CVIF configuration file."
    ),
    json_mode: bool = typer.Option(
        False, "--json", help="Output machine-readable JSON."
    ),
) -> None:
    """Pre-flight static security scan for deserialization exploits, zip bombs, and corrupt headers."""
    resolved_path = resolve_cli_path(model_path)
    if not resolved_path.is_file():
        emit_result({"error": f"Model file not found: {resolved_path}"}, json_mode=json_mode)
        raise typer.Exit(code=EXIT_CLI_ERROR)

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

    res_data = {
        "model_path": str(resolved_path),
        "is_safe": is_safe,
        "detected_format": detected_format,
        "file_hash": file_hash,
        "file_size_bytes": file_size_bytes,
        "errors": errors,
        "warnings": warnings,
        "status": "PASSED" if is_safe else "UNSAFE_MODEL_DETECTED",
    }

    def format_human(info: dict) -> None:
        sys.stdout.write(
            f"Model File Safety Pre-Flight Scan\n"
            f"File Path    : {info['model_path']}\n"
            f"Format       : {info['detected_format']}\n"
            f"Safety Status: {'SAFE' if info['is_safe'] else 'UNSAFE (SECURITY THREAT DETECTED)'}\n"
            f"File Size    : {info['file_size_bytes']} bytes\n"
            f"SHA-256      : {info['file_hash']}\n"
        )
        if info["errors"]:
            sys.stdout.write("Errors Detected:\n")
            for err in info["errors"]:
                sys.stdout.write(f"  - {err}\n")
        sys.stdout.flush()

    emit_result(res_data, json_mode=json_mode, human_formatter=format_human)

    if not is_safe:
        raise typer.Exit(code=EXIT_MODEL_INTEGRITY_FINDING)
    raise typer.Exit(code=EXIT_SUCCESS)


@model_app.command("scan")
@cli_error_boundary
def model_scan(
    model_path: Path = typer.Option(
        ..., "--model-path", "-m", help="Path to candidate model weight file."
    ),
    reference_weights: Optional[Path] = typer.Option(
        None, "--reference-weights", "-r", help="Path to golden baseline weights."
    ),
    session_id: Optional[UUID] = typer.Option(
        None, "--session-id", "-s", help="Analysis session UUID."
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to CVIF configuration file."
    ),
    json_mode: bool = typer.Option(
        False, "--json", help="Output machine-readable JSON."
    ),
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Save scan output JSON to file."
    ),
) -> None:
    """Execute model integrity test battery (MT-1 to MT-4) against candidate model."""
    ctx = get_runtime_context(config_path=config)
    try:
        resolved_model = resolve_cli_path(model_path)
        if not resolved_model.is_file():
            emit_result({"error": f"Model file not found: {resolved_model}"}, json_mode=json_mode)
            raise typer.Exit(code=EXIT_CLI_ERROR)

        # 1. Enforce safety scan prior to loading
        validate_model_file_safety(resolved_model)

        candidate_adapter = _resolve_model_adapter(resolved_model)
        reference_adapter: Optional[ModelAdapter] = None
        if reference_weights:
            resolved_ref = resolve_cli_path(reference_weights)
            if resolved_ref.is_file():
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

        sess_uuid = session_id or uuid4()
        session = orchestrator.run_analysis(
            candidate_model=candidate_adapter,
            reference_model=reference_adapter,
            battery=battery,
            session_id=sess_uuid,
            operator_id="cvif_cli",
        )

        findings_list = [f.model_dump(mode="json") for f in (session.findings or [])]
        has_severe_finding = any(
            f.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
            for f in (session.findings or [])
        )

        scan_result = {
            "session_id": str(session.session_id),
            "asset_id": str(session.asset_id),
            "status": session.status.value,
            "total_findings": len(findings_list),
            "has_critical_findings": has_severe_finding,
            "executed_analyses": session.executed_analyses,
            "findings": findings_list,
        }

        if output_file:
            from cvif.cli.output import serialize_data
            resolved_out = resolve_cli_path(output_file)
            resolved_out.parent.mkdir(parents=True, exist_ok=True)
            resolved_out.write_text(serialize_data(scan_result), encoding="utf-8")

        def format_human(info: dict) -> None:
            sys.stdout.write(
                f"Model Integrity Scan (MT-1 to MT-4)\n"
                f"Session ID       : {info['session_id']}\n"
                f"Asset ID         : {info['asset_id']}\n"
                f"Total Findings   : {info['total_findings']}\n"
                f"Critical/High    : {'YES (MODEL THREAT DETECTED)' if info['has_critical_findings'] else 'NO'}\n"
            )
            for finding in info["findings"]:
                sys.stdout.write(
                    f"  - [{finding['severity']}] {finding['threat_id']}: {finding['title']} (conf: {finding['confidence']})\n"
                )
            sys.stdout.flush()

        emit_result(scan_result, json_mode=json_mode, human_formatter=format_human)

        if has_severe_finding:
            raise typer.Exit(code=EXIT_MODEL_INTEGRITY_FINDING)
        raise typer.Exit(code=EXIT_SUCCESS)
    finally:
        ctx.close()
