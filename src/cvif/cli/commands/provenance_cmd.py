"""Inference provenance verification command for CVIF CLI."""

from pathlib import Path
import sys
from typing import Optional

import typer

from cvif.cli.commands.common import get_runtime_context, resolve_cli_path
from cvif.cli.error_handler import cli_error_boundary
from cvif.cli.exit_codes import (
    EXIT_CLI_ERROR,
    EXIT_PROVENANCE_FAILED,
    EXIT_SUCCESS,
)
from cvif.cli.output import emit_result
from cvif.core.enums import ProvenanceOutcome
from cvif.core.schemas import InferenceRecord
from cvif.provenance.verifier import InferenceProvenanceVerifier

provenance_app = typer.Typer(help="Verify multi-contributor inference provenance and cryptographic bindings (IT-1 to IT-5).")


@provenance_app.command("verify")
@cli_error_boundary
def provenance_verify(
    record_file: Optional[Path] = typer.Option(
        None, "--record-file", "-r", help="Path to JSON file containing InferenceRecord."
    ),
    record_json: Optional[str] = typer.Option(
        None, "--record-json", help="Raw JSON string representing InferenceRecord."
    ),
    raw_image: Optional[Path] = typer.Option(
        None, "--raw-image", "-i", help="Path to input raw image file for SHA-256 hash cross-verification."
    ),
    model_digest: Optional[str] = typer.Option(
        None, "--model-digest", "-m", help="Expected model weight SHA-256 hex digest."
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to CVIF configuration file."
    ),
    tolerance_seconds: float = typer.Option(
        86400.0, "--tolerance", "-t", help="Clock skew tolerance in seconds (default: 86400.0 / 24h)."
    ),
    json_mode: bool = typer.Option(
        False, "--json", help="Output machine-readable JSON."
    ),
) -> None:
    """Verify cryptographic binding, contributor key validity, timestamp freshness, and replay nonces."""
    if not record_file and not record_json:
        emit_result(
            {"error": "Either --record-file or --record-json must be provided."},
            json_mode=json_mode,
        )
        raise typer.Exit(code=EXIT_CLI_ERROR)

    ctx = get_runtime_context(config_path=config)
    try:
        raw_content: str
        if record_file:
            resolved_path = resolve_cli_path(record_file)
            if not resolved_path.is_file():
                emit_result({"error": f"Record file not found: {resolved_path}"}, json_mode=json_mode)
                raise typer.Exit(code=EXIT_CLI_ERROR)
            raw_content = resolved_path.read_text(encoding="utf-8")
        else:
            raw_content = str(record_json)

        inference_record = InferenceRecord.model_validate_json(raw_content)

        raw_image_resolved: Optional[Path] = None
        if raw_image:
            raw_image_resolved = resolve_cli_path(raw_image)

        verifier = InferenceProvenanceVerifier(
            key_store=ctx.keystore,
            db_manager=ctx.db,
            tolerance_seconds=tolerance_seconds,
        )

        res = verifier.verify_record(
            record=inference_record,
            raw_image=raw_image_resolved,
            registered_model_digest=model_digest,
            enforce_replay_checks=True,
        )

        res_data = {
            "record_id": str(inference_record.record_id),
            "session_id": str(inference_record.session_id),
            "contributor_id": inference_record.producer_id or inference_record.signing_key_id or "Unknown",
            "status": res.status.value,
            "is_verified": res.is_valid,
            "is_valid": res.is_valid,
            "findings_count": len(res.findings or []),
            "findings": [f.model_dump(mode="json") for f in (res.findings or [])],
            "details": res.details or {},
        }

        def format_human(info: dict) -> None:
            sys.stdout.write(
                f"Inference Provenance Verification Report\n"
                f"Record ID     : {info['record_id']}\n"
                f"Producer/Key  : {info['contributor_id']}\n"
                f"Status        : {info['status']}\n"
                f"Verified Valid: {'YES' if info['is_valid'] else 'NO (PROVENANCE REJECTED)'}\n"
            )
            for f in info["findings"]:
                sys.stdout.write(f"  - [{f['severity']}] {f['threat_id']}: {f['title']}\n")
            sys.stdout.flush()

        emit_result(res_data, json_mode=json_mode, human_formatter=format_human)

        if not res.is_valid or res.status != ProvenanceOutcome.VERIFIED:
            raise typer.Exit(code=EXIT_PROVENANCE_FAILED)
        raise typer.Exit(code=EXIT_SUCCESS)
    finally:
        ctx.close()
