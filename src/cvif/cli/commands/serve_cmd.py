"""Server startup command for CVIF CLI (Phase 10)."""

import logging
from pathlib import Path
from typing import Optional

import typer
import uvicorn

from cvif.cli.error_handler import cli_error_boundary
from cvif.cli.exit_codes import EXIT_CLI_ERROR, EXIT_SUCCESS
from cvif.core.config import load_config
from cvif.core.exceptions import ConfigurationError

logger = logging.getLogger("cvif.cli.serve")

serve_app = typer.Typer(help="Start the CVIF REST API server.")


@serve_app.callback(invoke_without_command=True)
@cli_error_boundary
def serve_command(
    host: Optional[str] = typer.Option(
        None, "--host", "-h", help="Bind host IP address (default: 127.0.0.1)."
    ),
    port: Optional[int] = typer.Option(
        None, "--port", "-p", help="Bind port number (default: 8000)."
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to custom CVIF configuration file."
    ),
    reload: bool = typer.Option(
        False, "--reload", help="Enable server auto-reload (development only)."
    ),
) -> None:
    """Run the CVIF REST API server using Uvicorn."""
    cfg = load_config(config)

    bind_host = host or cfg.api.host or "127.0.0.1"
    bind_port = port or cfg.api.port or 8000

    # Enforce safe host binding: binding to non-localhost requires explicit allow_remote_binding
    if bind_host not in ("127.0.0.1", "localhost") and not cfg.api.allow_remote_binding:
        raise ConfigurationError(
            f"Binding to non-loopback host '{bind_host}' is blocked by security policy. "
            "Set api.allow_remote_binding=true in configuration to allow remote interfaces.",
            details={"host": bind_host},
        )

    typer.echo(f"Starting CVIF REST API on {bind_host}:{bind_port} (Air-gap safe)")
    
    from cvif.api.main import create_app

    app = create_app(config=cfg, config_path=str(config) if config else None)
    uvicorn.run(app, host=bind_host, port=bind_port, reload=reload, log_level="info")
