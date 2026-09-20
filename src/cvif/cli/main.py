"""Master entry point for the Computer Vision Integrity Assurance Framework (CVIF) CLI.

Orchestrates all local CLI command groups:
  cvif dataset ...
  cvif data ...
  cvif model ...
  cvif provenance ...
  cvif shift ...
  cvif assess ...
  cvif evidence ...
  cvif audit ...
  cvif status
  cvif version
"""

import sys
from typing import Optional

import typer

from cvif.cli.commands.assess_cmd import assess_app
from cvif.cli.commands.audit_cmd import audit_app
from cvif.cli.commands.dataset_cmd import data_app, dataset_app
from cvif.cli.commands.evidence_cmd import evidence_app
from cvif.cli.commands.model_cmd import model_app
from cvif.cli.commands.provenance_cmd import provenance_app
from cvif.cli.commands.serve_cmd import serve_app
from cvif.cli.commands.shift_cmd import shift_app
from cvif.cli.commands.status_cmd import status_app
from cvif.cli.commands.version_cmd import version_app
from cvif.version import __schema_version__, __version__

app = typer.Typer(
    name="cvif",
    help="Computer Vision Integrity Assurance Framework (CVIF) — Local Trust Assurance CLI.",
    no_args_is_help=True,
    add_completion=False,
)

# Register Subcommand Groups
app.add_typer(dataset_app, name="dataset", help="Dataset ingestion and cataloging.")
app.add_typer(data_app, name="data", help="Dataset integrity analysis (DT-1 to DT-6).")
app.add_typer(model_app, name="model", help="Model file safety and model integrity analysis (MT-1 to MT-4).")
app.add_typer(provenance_app, name="provenance", help="Inference provenance verification (IT-1 to IT-5).")
app.add_typer(shift_app, name="shift", help="Distribution shift analysis (DS-1 to DS-4).")
app.add_typer(assess_app, name="assess", help="Synthesize holistic assurance verdicts.")
app.add_typer(evidence_app, name="evidence", help="Evidence store inspection, verification, and packaging.")
app.add_typer(audit_app, name="audit", help="Tamper-evident audit ledger inspection.")
app.add_typer(status_app, name="status", help="System health and component diagnostics.")
app.add_typer(version_app, name="version", help="Framework and schema version metadata.")
app.add_typer(serve_app, name="serve", help="Start the CVIF REST API server.")


def _version_callback(value: bool) -> None:
    if value:
        sys.stdout.write(f"cvif version {__version__} (schema {__schema_version__})\n")
        sys.stdout.flush()
        raise typer.Exit(code=0)


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show CVIF framework version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """CVIF Command-Line Interface for air-gapped computer vision pipeline assurance."""
    pass


def run_cli() -> None:
    """Main binary entrypoint executed by console script."""
    app()


if __name__ == "__main__":
    run_cli()
