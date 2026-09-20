"""Version command for CVIF CLI."""

import platform
import sys
from typing import Optional

import typer

from cvif.cli.error_handler import cli_error_boundary
from cvif.cli.exit_codes import EXIT_SUCCESS
from cvif.cli.output import emit_result
from cvif.version import __schema_version__, __version__

version_app = typer.Typer(help="Display CVIF build and framework version information.")


@version_app.callback(invoke_without_command=True)
@cli_error_boundary
def version_command(
    json_mode: bool = typer.Option(
        False, "--json", help="Output machine-readable JSON."
    ),
) -> None:
    """Display CVIF framework version, architecture version, and runtime platform."""
    data = {
        "version": __version__,
        "schema_version": __schema_version__,
        "architecture_version": "0.2-REVISED",
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "air_gap_enforced": True,
    }

    def format_human(info: dict) -> None:
        sys.stdout.write(
            f"Computer Vision Integrity Assurance Framework (CVIF)\n"
            f"Framework Version    : {info['version']}\n"
            f"Schema Version       : {info['schema_version']}\n"
            f"Architecture Release : {info['architecture_version']}\n"
            f"Python Runtime       : {info['python_version']} ({info['platform']})\n"
            f"Air-Gap Confinement  : {'ENABLED' if info['air_gap_enforced'] else 'DISABLED'}\n"
        )
        sys.stdout.flush()

    emit_result(data, json_mode=json_mode, human_formatter=format_human)
    raise typer.Exit(code=EXIT_SUCCESS)
