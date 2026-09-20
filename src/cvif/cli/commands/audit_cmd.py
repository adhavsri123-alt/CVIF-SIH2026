"""Audit ledger verification command for CVIF CLI."""

from pathlib import Path
import sys
from typing import Optional

import typer

from cvif.audit.logger import AuditLogger
from cvif.cli.commands.common import get_runtime_context
from cvif.cli.error_handler import cli_error_boundary
from cvif.cli.exit_codes import EXIT_CLI_ERROR, EXIT_SUCCESS, EXIT_TAMPER_DETECTED
from cvif.cli.output import emit_result

audit_app = typer.Typer(help="Manage and verify tamper-evident cryptographic audit logs.")


@audit_app.command("verify")
@cli_error_boundary
def audit_verify(
    log_file: Optional[Path] = typer.Option(
        None, "--log-file", "-l", help="Explicit path to audit.jsonl log file."
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to CVIF configuration file."
    ),
    json_mode: bool = typer.Option(
        False, "--json", help="Output machine-readable JSON."
    ),
) -> None:
    """Verify monotonic SHA-256 hash linkage of the audit ledger."""
    ctx = get_runtime_context(config_path=config)
    try:
        target_log = log_file or ctx.config.audit.audit_log_path
        if not target_log.is_file():
            res = {
                "verified": False,
                "error": f"Audit log file not found: {target_log}",
                "log_file": str(target_log),
            }
            emit_result(res, json_mode=json_mode)
            raise typer.Exit(code=EXIT_CLI_ERROR)

        logger = AuditLogger(target_log, auto_verify_on_init=False)
        chain_res = logger.verify_chain()
        is_valid = chain_res.is_valid
        broken_idx = chain_res.failed_event_index

        result = {
            "verified": is_valid,
            "broken_index": broken_idx,
            "total_events": chain_res.total_events,
            "verified_events": chain_res.verified_events,
            "error_message": chain_res.error_message,
            "log_file": str(target_log),
            "status": "VALID" if is_valid else "TAMPER_DETECTED",
        }

        def format_human(info: dict) -> None:
            sys.stdout.write(
                f"Audit Chain Verification Report\n"
                f"Log File      : {info['log_file']}\n"
                f"Status        : {info['status']}\n"
                f"Chain Intact  : {info['verified']}\n"
            )
            if not info["verified"]:
                sys.stdout.write(f"Broken Entry  : Block #{info['broken_index']}\n")
            sys.stdout.flush()

        emit_result(result, json_mode=json_mode, human_formatter=format_human)

        if not is_valid:
            raise typer.Exit(code=EXIT_TAMPER_DETECTED)
        raise typer.Exit(code=EXIT_SUCCESS)
    finally:
        ctx.close()
