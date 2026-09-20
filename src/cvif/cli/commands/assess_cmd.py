"""Assurance verdict aggregation and assessment command for CVIF CLI."""

from pathlib import Path
import sys
from typing import Optional
from uuid import UUID

import typer

from cvif.analysis.assurance.orchestrator import AssuranceOrchestrator
from cvif.cli.commands.common import get_runtime_context, resolve_cli_path
from cvif.cli.error_handler import cli_error_boundary
from cvif.cli.exit_codes import (
    EXIT_ASSURANCE_QUARANTINE,
    EXIT_ASSURANCE_REVIEW,
    EXIT_NOT_FOUND,
    EXIT_SUCCESS,
)
from cvif.cli.output import emit_result, serialize_data
from cvif.core.enums import Disposition

assess_app = typer.Typer(help="Synthesize and evaluate holistic assurance verdicts across multi-phase findings.")


@assess_app.callback(invoke_without_command=True)
@cli_error_boundary
def assess_command(
    session_id: UUID = typer.Option(
        ..., "--session-id", "-s", help="Analysis session UUID to synthesize assurance verdict for."
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to CVIF configuration file."
    ),
    json_mode: bool = typer.Option(
        False, "--json", help="Output machine-readable JSON."
    ),
    output_file: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Save synthesized verdict JSON to file."
    ),
) -> None:
    """Evaluate session findings against weighted assurance rules and emit authoritative verdict."""
    ctx = get_runtime_context(config_path=config)
    try:
        session = ctx.db.get_session(session_id)
        if session is None:
            emit_result(
                {"error": f"Session not found in catalogue database: {session_id}"},
                json_mode=json_mode,
            )
            raise typer.Exit(code=EXIT_NOT_FOUND)

        orchestrator = AssuranceOrchestrator(
            config=ctx.config.assurance,
            db_manager=ctx.db,
            audit_logger=ctx.audit,
        )

        verdict = orchestrator.evaluate_session(session, operator_id="cvif_cli")
        verdict_data = verdict.model_dump(mode="json")

        if output_file:
            resolved_out = resolve_cli_path(output_file)
            resolved_out.parent.mkdir(parents=True, exist_ok=True)
            resolved_out.write_text(serialize_data(verdict_data), encoding="utf-8")

        def format_human(info: dict) -> None:
            disposition = info["disposition"]
            badge = {
                "ACCEPT": "[ACCEPT - PIPELINE CLEARED]",
                "REVIEW": "[REVIEW - OPERATOR SCRUTINY REQUIRED]",
                "QUARANTINE": "[QUARANTINE - CRITICAL SECURITY VETO]",
            }.get(disposition, disposition)

            sys.stdout.write(
                f"CVIF Assurance Verdict Card\n"
                f"Verdict ID           : {info['verdict_id']}\n"
                f"Session ID           : {info['session_id']}\n"
                f"Asset ID             : {info['asset_id']}\n"
                f"Final Disposition    : {badge}\n"
                f"Composite Risk Score : {info['composite_risk_score']:.4f}\n"
                f"Critical Veto Applied: {'YES' if info['critical_veto_applied'] else 'NO'}\n"
                f"Contributing Findings: {len(info['contributing_finding_ids'])}\n"
            )
            sys.stdout.write("Dimension Risk Scores:\n")
            for dim, score in info.get("dimension_risks", {}).items():
                sys.stdout.write(f"  - {dim:<22}: {score:.4f}\n")
            if info.get("narrative_reasoning"):
                sys.stdout.write(f"Reasoning Summary    : {info['narrative_reasoning']}\n")
            sys.stdout.flush()

        emit_result(verdict_data, json_mode=json_mode, human_formatter=format_human)

        if verdict.disposition == Disposition.QUARANTINE:
            raise typer.Exit(code=EXIT_ASSURANCE_QUARANTINE)
        if verdict.disposition == Disposition.REVIEW:
            raise typer.Exit(code=EXIT_ASSURANCE_REVIEW)
        raise typer.Exit(code=EXIT_SUCCESS)
    finally:
        ctx.close()
