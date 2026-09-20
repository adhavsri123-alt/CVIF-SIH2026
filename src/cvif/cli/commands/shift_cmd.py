"""Distribution shift analysis command for CVIF CLI."""

from pathlib import Path
import sys
from typing import Optional
from uuid import UUID, uuid4

import typer

from cvif.analysis.distribution_shift.orchestrator import DistributionShiftOrchestrator
from cvif.cli.commands.common import get_runtime_context, resolve_cli_path
from cvif.cli.error_handler import cli_error_boundary
from cvif.cli.exit_codes import (
    EXIT_CLI_ERROR,
    EXIT_SHIFT_DETECTED,
    EXIT_SUCCESS,
)
from cvif.cli.output import emit_result
from cvif.features.statistical import StatisticalFeatureExtractor
from cvif.ingestion.gateway import IngestionGateway

shift_app = typer.Typer(help="Analyze distribution shifts between dataset populations (DS-1 to DS-4).")


@shift_app.command("analyze")
@cli_error_boundary
def shift_analyze(
    reference_data: Path = typer.Option(
        ..., "--reference-data", "-r", help="Path to golden baseline reference dataset."
    ),
    evaluation_data: Path = typer.Option(
        ..., "--evaluation-data", "-e", help="Path to operational evaluation dataset."
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
) -> None:
    """Compare baseline reference population with operational evaluation population across shift dimensions."""
    ctx = get_runtime_context(config_path=config)
    try:
        ref_path = resolve_cli_path(reference_data)
        eval_path = resolve_cli_path(evaluation_data)

        if not ref_path.is_dir():
            emit_result({"error": f"Reference dataset path not found: {ref_path}"}, json_mode=json_mode)
            raise typer.Exit(code=EXIT_CLI_ERROR)
        if not eval_path.is_dir():
            emit_result({"error": f"Evaluation dataset path not found: {eval_path}"}, json_mode=json_mode)
            raise typer.Exit(code=EXIT_CLI_ERROR)

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

        sess_uuid = session_id or uuid4()
        report, session = orchestrator.run_analysis(
            reference_dataset=ref_unified,
            evaluation_dataset=eval_unified,
            session_id=sess_uuid,
            operator_id="cvif_cli",
        )

        dims_dump = {
            dim_name: res.model_dump(mode="json")
            for dim_name, res in report.dimensions.items()
        }

        result_data = {
            "session_id": str(report.session_id),
            "reference_asset_id": str(report.reference_asset_id),
            "evaluation_asset_id": str(report.evaluation_asset_id),
            "overall_shift_detected": report.overall_shift_detected,
            "dimensions": dims_dump,
            "findings_count": len(session.findings or []),
            "findings": [f.model_dump(mode="json") for f in (session.findings or [])],
        }

        def format_human(info: dict) -> None:
            sys.stdout.write(
                f"Distribution Shift Analysis (DS-1 to DS-4)\n"
                f"Session ID       : {info['session_id']}\n"
                f"Shift Detected   : {'YES (DISTRIBUTION DRIFT DETECTED)' if info['overall_shift_detected'] else 'NO (STABLE)'}\n"
                f"Findings Emitted : {info['findings_count']}\n"
            )
            for dim_name, dim_info in info["dimensions"].items():
                sys.stdout.write(
                    f"  - Dimension {dim_name:<20}: shifted={dim_info['shift_detected']} "
                    f"(p_value={dim_info['p_value']:.4f}, stat={dim_info['statistic_value']:.4f})\n"
                )
            sys.stdout.flush()

        emit_result(result_data, json_mode=json_mode, human_formatter=format_human)

        if report.overall_shift_detected:
            raise typer.Exit(code=EXIT_SHIFT_DETECTED)
        raise typer.Exit(code=EXIT_SUCCESS)
    finally:
        ctx.close()
