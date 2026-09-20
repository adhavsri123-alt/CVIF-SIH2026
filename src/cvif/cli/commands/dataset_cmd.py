"""Dataset ingestion and data integrity scanning commands for CVIF CLI."""

from pathlib import Path
import sys
from typing import Optional
from uuid import UUID, uuid4

import typer

from cvif.analysis.orchestrator import DatasetIntegrityOrchestrator
from cvif.cli.commands.common import get_runtime_context, resolve_cli_path
from cvif.cli.error_handler import cli_error_boundary
from cvif.cli.exit_codes import (
    EXIT_CLI_ERROR,
    EXIT_DATA_INTEGRITY_FINDING,
    EXIT_SUCCESS,
)
from cvif.cli.output import emit_result
from cvif.core.enums import SeverityLevel
from cvif.features.statistical import StatisticalFeatureExtractor
from cvif.ingestion.gateway import IngestionGateway

dataset_app = typer.Typer(help="Ingest datasets and run data integrity analyses (DT-1 to DT-6).")
data_app = typer.Typer(help="Dataset integrity scanning commands.")


@dataset_app.command("ingest")
@cli_error_boundary
def dataset_ingest(
    data_dir: Path = typer.Option(
        ..., "--data-dir", "-d", help="Path to raw dataset directory on disk."
    ),
    format_name: str = typer.Option(
        "auto", "--format", "-f", help="Dataset format: coco, yolo, or auto."
    ),
    contributor_id: str = typer.Option(
        "local_contributor", "--contributor-id", help="Identifier of contributing organization."
    ),
    batch_id: Optional[str] = typer.Option(
        None, "--batch-id", help="Batch or shipment tracking identifier."
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to CVIF configuration file."
    ),
    json_mode: bool = typer.Option(
        False, "--json", help="Output machine-readable JSON."
    ),
) -> None:
    """Ingest, validate structure, compute perceptual dhashes, and catalog a dataset."""
    ctx = get_runtime_context(config_path=config)
    try:
        resolved_path = resolve_cli_path(data_dir)
        gateway = IngestionGateway(audit_logger=ctx.audit, db_manager=ctx.db)

        unified, val_res, asset_reg = gateway.ingest_dataset(
            dataset_path=resolved_path,
            contributor_id=contributor_id,
            batch_id=batch_id,
            compute_hashes=True,
        )

        result_data = {
            "status": "INGESTED",
            "asset_id": str(asset_reg.asset_id),
            "contributor_id": asset_reg.contributor_id,
            "format": asset_reg.format,
            "image_count": len(unified.images),
            "annotation_count": len(unified.annotations),
            "total_size_bytes": asset_reg.total_size_bytes,
            "validation": {
                "is_valid": val_res.is_valid,
                "warnings": val_res.warnings,
            },
        }

        def format_human(info: dict) -> None:
            sys.stdout.write(
                f"Dataset Ingestion Complete\n"
                f"Asset ID        : {info['asset_id']}\n"
                f"Contributor     : {info['contributor_id']}\n"
                f"Detected Format : {info['format']}\n"
                f"Images Indexed  : {info['image_count']}\n"
                f"Annotations     : {info['annotation_count']}\n"
                f"Payload Size    : {info['total_size_bytes']} bytes\n"
            )
            sys.stdout.flush()

        emit_result(result_data, json_mode=json_mode, human_formatter=format_human)
        raise typer.Exit(code=EXIT_SUCCESS)
    finally:
        ctx.close()


def _run_data_scan(
    data_dir: Path,
    session_id: Optional[UUID],
    contributor_id: Optional[str],
    config: Optional[Path],
    json_mode: bool,
    output_file: Optional[Path],
) -> None:
    ctx = get_runtime_context(config_path=config)
    try:
        resolved_path = resolve_cli_path(data_dir)
        gateway = IngestionGateway(audit_logger=ctx.audit, db_manager=ctx.db)

        unified, _, asset_reg = gateway.ingest_dataset(
            dataset_path=resolved_path,
            contributor_id=contributor_id or "analyst",
            compute_hashes=True,
        )

        sess_uuid = session_id or uuid4()
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
                f"Dataset Integrity Scan (DT-1 to DT-6)\n"
                f"Session ID       : {info['session_id']}\n"
                f"Asset ID         : {info['asset_id']}\n"
                f"Total Findings   : {info['total_findings']}\n"
                f"Critical/High    : {'YES (SECURITY THREAT)' if info['has_critical_findings'] else 'NO'}\n"
            )
            for finding in info["findings"]:
                sys.stdout.write(
                    f"  - [{finding['severity']}] {finding['threat_id']}: {finding['title']} (conf: {finding['confidence']})\n"
                )
            sys.stdout.flush()

        emit_result(scan_result, json_mode=json_mode, human_formatter=format_human)

        if has_severe_finding:
            raise typer.Exit(code=EXIT_DATA_INTEGRITY_FINDING)
        raise typer.Exit(code=EXIT_SUCCESS)
    finally:
        ctx.close()


@dataset_app.command("scan")
@cli_error_boundary
def dataset_scan(
    data_dir: Path = typer.Option(..., "--data-dir", "-d", help="Path to raw dataset directory."),
    session_id: Optional[UUID] = typer.Option(None, "--session-id", "-s", help="Analysis session UUID."),
    contributor_id: Optional[str] = typer.Option(None, "--contributor-id", help="Contributor ID."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="CVIF configuration file."),
    json_mode: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Save scan output JSON to file."),
) -> None:
    """Execute dataset integrity battery (DT-1 to DT-6) against a dataset."""
    _run_data_scan(data_dir, session_id, contributor_id, config, json_mode, output_file)


@data_app.command("scan")
@cli_error_boundary
def data_scan(
    data_dir: Path = typer.Option(..., "--data-dir", "-d", help="Path to raw dataset directory."),
    session_id: Optional[UUID] = typer.Option(None, "--session-id", "-s", help="Analysis session UUID."),
    contributor_id: Optional[str] = typer.Option(None, "--contributor-id", help="Contributor ID."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="CVIF configuration file."),
    json_mode: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Save scan output JSON to file."),
) -> None:
    """Execute dataset integrity battery (DT-1 to DT-6) against a dataset (alias for dataset scan)."""
    _run_data_scan(data_dir, session_id, contributor_id, config, json_mode, output_file)
