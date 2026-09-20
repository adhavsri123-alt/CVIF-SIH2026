"""Status and health inspection command for CVIF CLI."""

from pathlib import Path
import sys
from typing import Optional

import typer

from cvif.cli.commands.common import get_runtime_context
from cvif.cli.error_handler import cli_error_boundary
from cvif.cli.exit_codes import EXIT_CLI_ERROR, EXIT_SUCCESS, EXIT_TAMPER_DETECTED
from cvif.cli.output import emit_result

status_app = typer.Typer(help="Inspect local CVIF system health, database accessibility, and audit chain.")


@status_app.callback(invoke_without_command=True)
@cli_error_boundary
def status_command(
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to custom CVIF configuration file."
    ),
    json_mode: bool = typer.Option(
        False, "--json", help="Output machine-readable JSON."
    ),
) -> None:
    """Check availability of storage, catalogs, truststore, and audit ledger integrity."""
    ctx = get_runtime_context(config_path=config)
    try:
        # 1. Audit chain health
        chain_res = ctx.audit.verify_chain()
        chain_valid = chain_res.is_valid
        broken_idx = chain_res.failed_event_index

        # 2. Database connectivity
        db_accessible = False
        try:
            with ctx.db.transaction() as cur:
                cur.execute("SELECT 1;")
                db_accessible = True
        except Exception:
            db_accessible = False

        # 3. Directories existence
        storage_ok = (
            ctx.config.storage.data_dir.exists()
            and ctx.config.evidence.evidence_dir.exists()
        )

        status_data = {
            "status": "HEALTHY" if (chain_valid and db_accessible and storage_ok) else "DEGRADED",
            "audit_chain": {
                "intact": chain_valid,
                "broken_index": broken_idx,
                "total_events": chain_res.total_events,
                "verified_events": chain_res.verified_events,
                "log_file": str(ctx.config.audit.audit_log_path),
            },
            "database": {
                "accessible": db_accessible,
                "path": str(ctx.config.storage.catalog_db_path),
            },
            "evidence_store": {
                "directory": str(ctx.config.evidence.evidence_dir),
                "accessible": ctx.config.evidence.evidence_dir.is_dir(),
            },
            "truststore": {
                "directory": str(ctx.config.keystore.keystore_dir),
                "accessible": ctx.config.keystore.keystore_dir.is_dir(),
            },
        }

        def format_human(info: dict) -> None:
            sys.stdout.write(
                f"CVIF System Health Summary\n"
                f"Overall Status       : {info['status']}\n"
                f"Audit Chain Integrity: {'VALID' if info['audit_chain']['intact'] else 'COMPROMISED (index: ' + str(info['audit_chain']['broken_index']) + ')'}\n"
                f"Catalogue Database   : {'ONLINE' if info['database']['accessible'] else 'OFFLINE'} ({info['database']['path']})\n"
                f"Evidence Store Root  : {'ONLINE' if info['evidence_store']['accessible'] else 'OFFLINE'} ({info['evidence_store']['directory']})\n"
                f"KeyStore Truststore  : {'ONLINE' if info['truststore']['accessible'] else 'OFFLINE'} ({info['truststore']['directory']})\n"
            )
            sys.stdout.flush()

        emit_result(status_data, json_mode=json_mode, human_formatter=format_human)

        if not chain_valid:
            raise typer.Exit(code=EXIT_TAMPER_DETECTED)
        if not (db_accessible and storage_ok):
            raise typer.Exit(code=EXIT_CLI_ERROR)
        raise typer.Exit(code=EXIT_SUCCESS)
    finally:
        ctx.close()
