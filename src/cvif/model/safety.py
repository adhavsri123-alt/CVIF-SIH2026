"""Model file safety inspection and layered defense against hostile model files.

Implements pre-flight static safety scanning, ZIP archive analysis, forbidden
opcode detection, file size boundaries, and subprocess isolation execution.
"""

import hashlib
from multiprocessing import Process, Queue
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import zipfile

from cvif.core.exceptions import (
    InvalidModelError,
    PathTraversalError,
    ResourceExhaustionError,
    StorageError,
    UnsupportedFormatError,
)
from cvif.core.schemas import ModelSafetyResult


ALLOWED_MODEL_EXTENSIONS = {
    ".onnx": "onnx",
    ".pt": "pytorch",
    ".pth": "pytorch",
    ".torchscript": "torchscript",
    ".bin": "binary",
}

# Configurable default safety limits
DEFAULT_MAX_MODEL_SIZE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB
DEFAULT_MAX_SCAN_BYTES = 16 * 1024 * 1024               # 16 MB pre-scan window
DEFAULT_MAX_ZIP_RATIO = 100.0                           # Max decompression ratio
DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB
DEFAULT_SUBPROCESS_TIMEOUT_SECONDS = 30.0

# Suspicious opcodes and dangerous callable imports in pickle streams
UNSAFE_PICKLE_OPCODES = [
    b"cos\nsystem",
    b"cposix\nsystem",
    b"cnt\nsystem",
    b"cbuiltins\neval",
    b"cbuiltins\nexec",
    b"cbuiltins\n__import__",
    b"cbuiltins\ngetattr",
    b"cbuiltins\nopen",
    b"cbuiltins\ncompile",
    b"c__builtin__\neval",
    b"c__builtin__\nexec",
    b"c__builtin__\n__import__",
    b"subprocess",
    b"shutil",
    b"cpty\n",
    b"csocket\n",
    b"curllib",
    b"crequests",
    b"chttp.client",
    b"cctypes",
    b"cwinreg",
]


class ModelSafetyScanner:
    """Pre-flight static scanner and layered validation engine for untrusted model files."""

    def __init__(
        self,
        max_file_size_bytes: int = DEFAULT_MAX_MODEL_SIZE_BYTES,
        max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
        max_zip_ratio: float = DEFAULT_MAX_ZIP_RATIO,
        max_total_uncompressed_bytes: int = DEFAULT_MAX_TOTAL_UNCOMPRESSED_BYTES,
    ):
        self.max_file_size_bytes = max_file_size_bytes
        self.max_scan_bytes = max_scan_bytes
        self.max_zip_ratio = max_zip_ratio
        self.max_total_uncompressed_bytes = max_total_uncompressed_bytes

    def scan(self, file_path: Union[str, Path]) -> ModelSafetyResult:
        """Perform comprehensive pre-flight safety analysis on a model file."""
        path = Path(file_path).resolve()
        errors: List[str] = []
        warnings: List[str] = []
        sec_meta: Dict[str, Any] = {}

        if not path.is_file():
            raise StorageError(f"Model file not found: {path}")

        file_size = path.stat().st_size
        if file_size == 0:
            raise InvalidModelError(f"Model file {path.name} is empty (0 bytes)")

        if file_size > self.max_file_size_bytes:
            raise ResourceExhaustionError(
                f"Model file size ({file_size} bytes) exceeds maximum allowable limit "
                f"({self.max_file_size_bytes} bytes)"
            )

        ext = path.suffix.lower()
        if ext not in ALLOWED_MODEL_EXTENSIONS:
            raise UnsupportedFormatError(
                f"Unsupported model extension '{ext}'. Allowed extensions: {sorted(ALLOWED_MODEL_EXTENSIONS.keys())}"
            )

        detected_format = ALLOWED_MODEL_EXTENSIONS[ext]

        # Compute file hash
        h = hashlib.sha256()
        with path.open("rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        file_hash = h.hexdigest()

        # Check for ZIP archive (used by modern PyTorch and TorchScript)
        is_zip = False
        with path.open("rb") as f:
            magic = f.read(4)
            if magic.startswith(b"PK\x03\x04"):
                is_zip = True

        sec_meta["is_zip_archive"] = is_zip

        if is_zip:
            self._inspect_zip_archive(path, errors, warnings, sec_meta)
        else:
            self._inspect_raw_stream(path, file_size, errors, warnings)

        is_safe = len(errors) == 0

        result = ModelSafetyResult(
            is_safe=is_safe,
            detected_format=detected_format,
            file_size_bytes=file_size,
            file_hash=file_hash,
            warnings=warnings,
            errors=errors,
            security_metadata=sec_meta,
        )

        if not is_safe:
            raise InvalidModelError(
                f"Model safety check failed for {path.name}: {'; '.join(errors)}"
            )

        return result

    def _inspect_raw_stream(
        self,
        path: Path,
        file_size: int,
        errors: List[str],
        warnings: List[str],
    ) -> None:
        """Scan raw binary stream (pickle or ONNX) for forbidden opcodes and payloads."""
        scan_limit = min(file_size, self.max_scan_bytes)
        try:
            with path.open("rb") as f:
                header = f.read(scan_limit)
                for bad_sig in UNSAFE_PICKLE_OPCODES:
                    if bad_sig in header:
                        errors.append(
                            f"found dangerous opcode: {bad_sig.decode('ascii', errors='ignore').strip()}"
                        )
        except OSError as e:
            raise StorageError(f"Failed to inspect model file {path}: {e}") from e

    def _inspect_zip_archive(
        self,
        path: Path,
        errors: List[str],
        warnings: List[str],
        sec_meta: Dict[str, Any],
    ) -> None:
        """Inspect ZIP-based model files (TorchScript / PyTorch ZIP) without extracting."""
        try:
            with zipfile.ZipFile(path, "r") as zf:
                total_uncompressed = 0
                total_compressed = 0
                member_names = zf.namelist()
                sec_meta["member_count"] = len(member_names)

                for info in zf.infolist():
                    name = info.filename
                    # 1. Path traversal detection
                    if ".." in name or name.startswith("/") or name.startswith("\\"):
                        errors.append(f"Zip entry contains path traversal attempt: {name}")

                    # 2. Executable scripts check
                    lower_name = name.lower()
                    if lower_name.endswith((".sh", ".bat", ".exe", ".cmd", ".vbs", ".ps1")):
                        errors.append(f"Forbidden executable script inside model archive: {name}")

                    # 3. Compression ratio / bomb detection
                    total_uncompressed += info.file_size
                    total_compressed += max(1, info.compress_size)
                    if info.compress_size > 0:
                        ratio = info.file_size / info.compress_size
                        if ratio > self.max_zip_ratio and info.file_size > 10 * 1024 * 1024:
                            errors.append(
                                f"Suspicious compression ratio ({ratio:.1f}x) in archive member {name}"
                            )

                    # 4. Scan pickle files inside archive (e.g. data.pkl or archive/data.pkl)
                    if lower_name.endswith(".pkl") or lower_name.endswith("/data") or "pickle" in lower_name:
                        try:
                            member_data = zf.read(info)
                            scan_len = min(len(member_data), self.max_scan_bytes)
                            sample = member_data[:scan_len]
                            for bad_sig in UNSAFE_PICKLE_OPCODES:
                                if bad_sig in sample:
                                    errors.append(
                                        f"Dangerous opcode in archive member {name}: "
                                        f"{bad_sig.decode('ascii', errors='ignore').strip()}"
                                    )
                        except Exception as ex:
                            warnings.append(f"Could not scan internal archive member {name}: {ex}")

                sec_meta["total_uncompressed_bytes"] = total_uncompressed
                if total_uncompressed > self.max_total_uncompressed_bytes:
                    errors.append(
                        f"Total uncompressed archive size ({total_uncompressed} bytes) exceeds limit "
                        f"({self.max_total_uncompressed_bytes} bytes)"
                    )

        except zipfile.BadZipFile as e:
            errors.append(f"Malformed or corrupted ZIP model archive: {e}")
        except OSError as e:
            raise StorageError(f"Failed to inspect model archive {path}: {e}") from e


def scan_model_file(
    file_path: Union[str, Path],
    config: Optional[Dict[str, Any]] = None,
) -> ModelSafetyResult:
    """Convenience functional interface for model safety scanning."""
    cfg = config or {}
    scanner = ModelSafetyScanner(
        max_file_size_bytes=cfg.get("max_file_size_bytes", DEFAULT_MAX_MODEL_SIZE_BYTES),
        max_scan_bytes=cfg.get("max_scan_bytes", DEFAULT_MAX_SCAN_BYTES),
        max_zip_ratio=cfg.get("max_zip_ratio", DEFAULT_MAX_ZIP_RATIO),
    )
    return scanner.scan(file_path)


def validate_model_file_safety(
    file_path: Union[str, Path],
    format_hint: Optional[str] = None,
) -> str:
    """Backwards-compatible pre-flight validation entrypoint.
    
    Verifies file existence, allowed extension, and runs pre-flight safety scan.
    Returns detected format string or raises InvalidModelError / UnsupportedFormatError.
    """
    res = scan_model_file(file_path)
    return res.detected_format


def _isolated_worker(target_func: Callable, args: tuple, kwargs: dict, queue: Queue) -> None:
    """Helper worker process function."""
    try:
        res = target_func(*args, **kwargs)
        queue.put(("SUCCESS", res))
    except Exception as e:
        queue.put(("ERROR", str(e)))


def run_isolated_model_load(
    target_func: Callable[..., Any],
    *args: Any,
    timeout_seconds: float = DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
    **kwargs: Any,
) -> Any:
    """Execute model deserialization or inspection within an isolated worker process.
    
    Guards against segfaults, memory leaks, or unhandled crashes during unsafe operations.
    """
    queue: Queue = Queue()
    proc = Process(target=_isolated_worker, args=(target_func, args, kwargs, queue))
    proc.daemon = True
    proc.start()
    proc.join(timeout=timeout_seconds)

    if proc.is_alive():
        proc.terminate()
        proc.join(timeout=1.0)
        raise ResourceExhaustionError(
            f"Model operation exceeded timeout threshold of {timeout_seconds}s in isolated worker"
        )

    if queue.empty():
        exit_code = proc.exitcode
        raise InvalidModelError(
            f"Isolated model loader process terminated abnormally (exit code: {exit_code})"
        )

    status, value = queue.get()
    if status == "ERROR":
        raise InvalidModelError(f"Isolated model loader failed: {value}")
    return value

def _probe_addition_worker(x: int, y: int) -> int:
    """Built-in test worker for multiprocessing validation."""
    return x + y


def _probe_exception_worker() -> None:
    """Built-in failing test worker for multiprocessing validation."""
    raise ValueError("Simulated unpickling error")


def _build_isolated_env() -> dict:
    """Construct a minimal, hardened environment for isolated model subprocess.

    Explicitly provides the project ``src/`` directory as PYTHONPATH so the
    subprocess can resolve ``cvif.*`` imports.  Does NOT blindly inherit the
    caller's full environment — only a curated allowlist of system variables
    required for subprocess execution on Windows and POSIX.
    """
    import os
    import sys

    # Resolve project src/ directory (parent of cvif package: src/cvif/model/safety.py -> src/)
    src_dir = Path(__file__).resolve().parent.parent.parent
    project_pythonpath = str(src_dir)

    # Curated allowlist of system environment variables required for subprocess operation
    _ALLOWED_ENV_KEYS = {
        "PATH", "PATHEXT",                # Executable resolution
        "SystemRoot", "SYSTEMROOT",        # Windows system root
        "TEMP", "TMP",                     # Temporary file directories
        "HOME", "USERPROFILE",             # Home directory resolution
        "HOMEDRIVE", "HOMEPATH",           # Windows home path components
        "COMSPEC",                         # Windows command interpreter
        "WINDIR",                          # Windows directory
        "APPDATA", "LOCALAPPDATA",         # Windows app data paths
        "LANG", "LC_ALL", "LC_CTYPE",      # Locale settings
        "VIRTUAL_ENV",                     # Active virtual environment
    }

    env: dict = {}
    for key in _ALLOWED_ENV_KEYS:
        val = os.environ.get(key)
        if val is not None:
            env[key] = val

    # Explicitly set PYTHONPATH to the project source directory
    env["PYTHONPATH"] = project_pythonpath

    return env


def isolated_inspect_model_file(
    file_path: Union[str, Path],
    timeout_seconds: float = DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
) -> ModelSafetyResult:
    """Execute pre-flight model scan in a separate, disposable subprocess with memory/time boundaries."""
    import json
    import subprocess
    import sys

    path = Path(file_path).resolve()
    cmd = [sys.executable, "-m", "cvif.model.safety", str(path)]

    # Construct hardened environment — does not inherit full os.environ
    env = _build_isolated_env()

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            text=True,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired as e:
        raise ResourceExhaustionError(
            f"Model inspection timed out after {timeout_seconds}s in isolated subprocess"
        ) from e

    if proc.returncode != 0:
        err_msg = proc.stderr.strip() or f"Subprocess exited with code {proc.returncode}"
        raise InvalidModelError(f"Isolated safety scan failed: {err_msg}")

    try:
        data = json.loads(proc.stdout)
        return ModelSafetyResult.model_validate(data)
    except Exception as e:
        raise InvalidModelError(f"Failed to parse isolated scan output: {e}") from e



if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        try:
            res = scan_model_file(target)
            print(res.to_canonical_json())
            sys.exit(0)
        except Exception as ex:
            print(str(ex), file=sys.stderr)
            sys.exit(1)
    else:
        print("Usage: python -m cvif.model.safety <model_path>", file=sys.stderr)
        sys.exit(2)
