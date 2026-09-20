"""Evidence store inspection, cryptographic verification, and export commands for CVIF CLI."""

import json
from pathlib import Path
import sys
from typing import Optional
from uuid import UUID
import zipfile

import typer

from cvif.cli.commands.common import get_runtime_context, resolve_cli_path
from cvif.cli.error_handler import cli_error_boundary
from cvif.cli.exit_codes import (
    EXIT_CLI_ERROR,
    EXIT_NOT_FOUND,
    EXIT_SUCCESS,
    EXIT_TAMPER_DETECTED,
)
from cvif.cli.output import emit_result, serialize_data
from cvif.core.exceptions import TamperDetectedError
from cvif.crypto.hashing import sha256_bytes, sha256_file

evidence_app = typer.Typer(help="Query, inspect, verify, and export write-once tamper-evident evidence.")


@evidence_app.command("list")
@cli_error_boundary
def evidence_list(
    session_id: Optional[UUID] = typer.Option(None, "--session-id", "-s", help="Filter by session UUID."),
    finding_id: Optional[UUID] = typer.Option(None, "--finding-id", "-f", help="Filter by finding UUID."),
    threat_id: Optional[str] = typer.Option(None, "--threat-id", "-t", help="Filter by threat taxonomy ID (e.g. DT-1, MT-3)."),
    evidence_type: Optional[str] = typer.Option(None, "--type", help="Filter by evidence type (STATISTICAL, ARTIFACT, etc.)."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to CVIF configuration file."),
    json_mode: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
) -> None:
    """List indexed evidence records matching relational filter criteria."""
    ctx = get_runtime_context(config_path=config)
    try:
        if threat_id:
            rows = ctx.db.get_evidence_by_threat_id(threat_id)
        else:
            rows = ctx.db.list_evidence_records(
                session_id=session_id,
                finding_id=finding_id,
                evidence_type=evidence_type,
            )

        items = []
        for r in rows:
            items.append({
                "evidence_id": r["evidence_id"],
                "session_id": r["session_id"],
                "finding_id": r["finding_id"],
                "evidence_type": r["evidence_type"],
                "content_hash": r["content_hash"],
                "created_at": r["created_at"],
            })

        def format_human(data: list) -> None:
            sys.stdout.write(f"Total Evidence Records: {len(data)}\n")
            sys.stdout.write(f"{'Evidence ID':<38} {'Type':<15} {'Content Hash (first 16)':<20} {'Created At'}\n")
            sys.stdout.write("-" * 95 + "\n")
            for item in data:
                sys.stdout.write(
                    f"{item['evidence_id']:<38} {item['evidence_type']:<15} {item['content_hash'][:16]:<20} {item['created_at']}\n"
                )
            sys.stdout.flush()

        emit_result(items, json_mode=json_mode, human_formatter=format_human)
        raise typer.Exit(code=EXIT_SUCCESS)
    finally:
        ctx.close()


@evidence_app.command("get")
@cli_error_boundary
def evidence_get(
    evidence_id: UUID = typer.Option(..., "--id", help="UUID of the EvidenceRecord to retrieve."),
    no_verify: bool = typer.Option(False, "--no-verify", help="Disable cryptographic hash and artifact digest checks."),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Save canonical JSON to file."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to CVIF configuration file."),
    json_mode: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
) -> None:
    """Retrieve an evidence record by ID, verifying its SHA-256 integrity and linked artifacts."""
    ctx = get_runtime_context(config_path=config)
    try:
        verify = not no_verify
        record = ctx.evidence.get_evidence(evidence_id, verify_integrity=verify)
        if record is None:
            emit_result({"error": f"Evidence record not found: {evidence_id}"}, json_mode=json_mode)
            raise typer.Exit(code=EXIT_NOT_FOUND)

        record_data = record.model_dump(mode="json")

        if output_file:
            resolved_out = resolve_cli_path(output_file)
            resolved_out.parent.mkdir(parents=True, exist_ok=True)
            resolved_out.write_text(record.to_canonical_json(), encoding="utf-8")

        def format_human(info: dict) -> None:
            sys.stdout.write(
                f"Evidence Record Details\n"
                f"Evidence ID   : {info['evidence_id']}\n"
                f"Finding ID    : {info['finding_id']}\n"
                f"Session ID    : {info['session_id']}\n"
                f"Evidence Type : {info['evidence_type']}\n"
                f"Narrative     : {info['narrative']}\n"
                f"Methodology   : {info['methodology']}\n"
                f"Timestamp     : {info['timestamp']}\n"
            )
            if info.get("metrics"):
                sys.stdout.write(f"Metrics       : {json.dumps(info['metrics'])}\n")
            if info.get("artifacts"):
                sys.stdout.write(f"Artifacts     : {len(info['artifacts'])} linked artifact(s)\n")
            sys.stdout.flush()

        emit_result(record_data, json_mode=json_mode, human_formatter=format_human)
        raise typer.Exit(code=EXIT_SUCCESS)
    finally:
        ctx.close()


@evidence_app.command("verify")
@cli_error_boundary
def evidence_verify(
    session_id: Optional[UUID] = typer.Option(None, "--session-id", "-s", help="Optionally scope consistency check to specific session."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to CVIF configuration file."),
    json_mode: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
) -> None:
    """Perform full consistency audit cross-checking physical files against SQLite digests."""
    ctx = get_runtime_context(config_path=config)
    try:
        audit_res = ctx.evidence.verify_store_consistency(session_id=session_id)

        def format_human(info: dict) -> None:
            sys.stdout.write(
                f"Evidence Store Consistency Audit\n"
                f"Total Records   : {info['total_records']}\n"
                f"Total Artifacts : {info['total_artifacts']}\n"
                f"Consistent      : {'YES' if info['is_consistent'] else 'NO (CORRUPTION OR TAMPER DETECTED)'}\n"
            )
            if info["missing_records"]:
                sys.stdout.write(f"Missing Records : {info['missing_records']}\n")
            if info["tampered_records"]:
                sys.stdout.write(f"Tampered Records: {info['tampered_records']}\n")
            if info["missing_artifacts"]:
                sys.stdout.write(f"Missing Artifacts: {info['missing_artifacts']}\n")
            if info["tampered_artifacts"]:
                sys.stdout.write(f"Tampered Artifacts: {info['tampered_artifacts']}\n")
            if info.get("orphan_evidence"):
                sys.stdout.write(f"Orphan Evidence : {info['orphan_evidence']}\n")
            if info.get("orphan_artifacts"):
                sys.stdout.write(f"Orphan Artifacts: {info['orphan_artifacts']}\n")
            sys.stdout.flush()

        emit_result(audit_res, json_mode=json_mode, human_formatter=format_human)

        if not audit_res["is_consistent"]:
            raise typer.Exit(code=EXIT_TAMPER_DETECTED)
        raise typer.Exit(code=EXIT_SUCCESS)
    finally:
        ctx.close()


@evidence_app.command("export")
@cli_error_boundary
def evidence_export(
    session_id: UUID = typer.Option(..., "--session-id", "-s", help="Session UUID to package and export."),
    output_path: Path = typer.Option(..., "--output", "-o", help="Target archive path (e.g. session_bundle.cvif)."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to CVIF configuration file."),
    json_mode: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
) -> None:
    """Package session evidence records, diagnostic artifacts, and SHA-256 manifest into a .cvif archive."""
    ctx = get_runtime_context(config_path=config)
    try:
        # 1. Pre-export consistency check
        audit_res = ctx.evidence.verify_store_consistency(session_id=session_id)
        if not audit_res["is_consistent"]:
            emit_result({
                "error": "Cannot export session with corrupted or tampered evidence.",
                "audit": audit_res,
            }, json_mode=json_mode)
            raise typer.Exit(code=EXIT_TAMPER_DETECTED)

        records = ctx.evidence.list_evidence_for_session(session_id)
        if not records:
            emit_result({"error": f"No evidence records found for session: {session_id}"}, json_mode=json_mode)
            raise typer.Exit(code=EXIT_NOT_FOUND)

        dest_file = resolve_cli_path(output_path)
        dest_file.parent.mkdir(parents=True, exist_ok=True)

        manifest = {
            "session_id": str(session_id),
            "files": {},
        }

        with zipfile.ZipFile(dest_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rec in records:
                rel_rec_path = f"evidence/{rec.evidence_id}.json"
                rec_bytes = rec.to_canonical_bytes()
                zf.writestr(rel_rec_path, rec_bytes)
                manifest["files"][rel_rec_path] = sha256_bytes(rec_bytes)

                if rec.artifacts:
                    for art in rec.artifacts:
                        art_bytes = ctx.evidence.read_artifact(session_id, art.path, verify_integrity=True)
                        zf.writestr(art.path, art_bytes)
                        manifest["files"][art.path] = sha256_bytes(art_bytes)

            # Write manifest
            manifest_json = json.dumps(manifest, indent=2, sort_keys=True)
            zf.writestr("manifest.json", manifest_json)

        archive_digest = sha256_file(dest_file)
        export_summary = {
            "session_id": str(session_id),
            "archive_path": str(dest_file),
            "total_records": len(records),
            "total_files": len(manifest["files"]),
            "sha256_manifest_digest": archive_digest,
        }

        def format_human(info: dict) -> None:
            sys.stdout.write(
                f"Session Evidence Export Complete\n"
                f"Archive Path : {info['archive_path']}\n"
                f"Records      : {info['total_records']}\n"
                f"Total Files  : {info['total_files']}\n"
                f"SHA-256      : {info['sha256_manifest_digest']}\n"
            )
            sys.stdout.flush()

        emit_result(export_summary, json_mode=json_mode, human_formatter=format_human)
        raise typer.Exit(code=EXIT_SUCCESS)
    finally:
        ctx.close()
