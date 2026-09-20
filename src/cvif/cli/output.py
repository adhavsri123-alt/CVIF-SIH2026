"""Output formatting and stream separation for CVIF CLI.

Enforces strict stdout / stderr isolation:
- stdout: Exclusively machine-readable JSON (in --json mode) or formatted human summaries.
- stderr: Diagnostics, progress messages, warnings, and error descriptions.
"""

from datetime import datetime
import json
from pathlib import Path
import sys
from typing import Any, Callable, Dict, List, Optional, Union
from uuid import UUID

from pydantic import BaseModel


def _json_serial(obj: Any) -> Any:
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, (datetime,)):
        return obj.isoformat()
    if isinstance(obj, (UUID, Path)):
        return str(obj)
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if hasattr(obj, "value"):
        return obj.value
    raise TypeError(f"Type {type(obj)} not serializable")


def serialize_data(data: Any) -> str:
    """Deterministic JSON serialization with sorted keys."""
    if isinstance(data, BaseModel):
        dumped = data.model_dump(mode="json")
    elif isinstance(data, list):
        dumped = [
            d.model_dump(mode="json") if isinstance(d, BaseModel) else d
            for d in data
        ]
    elif isinstance(data, dict):
        dumped = data
    else:
        dumped = data
    return json.dumps(dumped, indent=2, sort_keys=True, default=_json_serial)


def emit_result(
    data: Any,
    json_mode: bool = False,
    human_formatter: Optional[Callable[[Any], None]] = None,
) -> None:
    """Emit command output to stdout.
    
    In json_mode, writes strictly valid JSON to stdout.
    In human mode, uses human_formatter or fallback textual printer.
    """
    if json_mode:
        payload = serialize_data(data)
        sys.stdout.write(payload + "\n")
        sys.stdout.flush()
    else:
        if human_formatter is not None:
            human_formatter(data)
        else:
            if isinstance(data, (dict, list)):
                sys.stdout.write(serialize_data(data) + "\n")
            else:
                sys.stdout.write(str(data) + "\n")
            sys.stdout.flush()


def emit_diagnostic(message: str) -> None:
    """Emit diagnostic or informational message to stderr."""
    sys.stderr.write(f"{message}\n")
    sys.stderr.flush()


def emit_warning(message: str) -> None:
    """Emit warning message to stderr."""
    sys.stderr.write(f"[WARNING] {message}\n")
    sys.stderr.flush()


def emit_error(
    message: str,
    json_mode: bool = False,
    exit_code: int = 1,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Emit error message.
    
    In json_mode, writes JSON error descriptor to stderr to preserve pipeline integrity,
    or directly on stderr for debugging.
    """
    if json_mode:
        err_obj = {
            "status": "ERROR",
            "exit_code": exit_code,
            "message": message,
            "details": details or {},
        }
        sys.stderr.write(json.dumps(err_obj, indent=2, sort_keys=True) + "\n")
    else:
        sys.stderr.write(f"[ERROR] {message}\n")
    sys.stderr.flush()
