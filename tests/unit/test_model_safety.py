"""Unit tests for pre-flight static model safety scanner and layered defense."""

from pathlib import Path
import pytest
import zipfile

from cvif.core.exceptions import (
    InvalidModelError,
    ResourceExhaustionError,
    StorageError,
    UnsupportedFormatError,
)
from cvif.model.safety import (
    ModelSafetyScanner,
    run_isolated_model_load,
    scan_model_file,
    validate_model_file_safety,
)


def test_safety_valid_onnx_and_pytorch(temp_dir: Path):
    """Verify safe models pass pre-flight scanning."""
    # 1. Valid ONNX
    onnx_f = temp_dir / "clean_model.onnx"
    onnx_f.write_bytes(b"dummy_onnx_graph_bytes_1234567890")
    res = scan_model_file(onnx_f)
    assert res.is_safe is True
    assert res.detected_format == "onnx"
    assert len(res.file_hash) == 64

    # 2. Valid PyTorch raw
    pt_f = temp_dir / "clean_model.pt"
    pt_f.write_bytes(b"dummy_clean_pytorch_bytes_1234567890")
    res_pt = scan_model_file(pt_f)
    assert res_pt.is_safe is True
    assert res_pt.detected_format == "pytorch"


def test_safety_empty_and_nonexistent_files(temp_dir: Path):
    """Verify empty and non-existent files are rejected."""
    empty_f = temp_dir / "empty.pt"
    empty_f.write_bytes(b"")
    with pytest.raises(InvalidModelError):
        scan_model_file(empty_f)

    with pytest.raises(StorageError):
        scan_model_file(temp_dir / "nonexistent.pt")


def test_safety_unsupported_extensions(temp_dir: Path):
    """Verify unsupported extensions are rejected."""
    sh_f = temp_dir / "evil.sh"
    sh_f.write_bytes(b"#!/bin/bash\nrm -rf /")
    with pytest.raises(UnsupportedFormatError):
        scan_model_file(sh_f)


def test_safety_forbidden_pickle_opcodes(temp_dir: Path):
    """Verify forbidden execution opcodes in raw streams are rejected."""
    payloads = [
        b"cos\nsystem\n(S'calc.exe'tRp1.",
        b"cposix\nsystem\n(S'whoami'tRp1.",
        b"cbuiltins\neval\n(S'__import__(\"os\").system(\"ls\")'tRp1.",
        b"cbuiltins\nexec\n(S'import socket'tRp1.",
        b"cbuiltins\n__import__\n(S'os'tRp1.",
        b"subprocess.Popen",
        b"shutil.rmtree",
    ]
    for i, payload in enumerate(payloads):
        f = temp_dir / f"evil_{i}.pt"
        f.write_bytes(payload)
        with pytest.raises(InvalidModelError) as exc_info:
            scan_model_file(f)
        assert "dangerous opcode" in str(exc_info.value).lower()


def test_safety_zip_archive_path_traversal(temp_dir: Path):
    """Verify ZIP archives containing path traversal entries are rejected."""
    zip_f = temp_dir / "traversal.torchscript"
    with zipfile.ZipFile(zip_f, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        zf.writestr("model.json", "{}")

    with pytest.raises(InvalidModelError) as exc_info:
        scan_model_file(zip_f)
    assert "path traversal" in str(exc_info.value).lower()


def test_safety_zip_archive_forbidden_scripts(temp_dir: Path):
    """Verify ZIP archives containing executable scripts are rejected."""
    zip_f = temp_dir / "evil_script.pt"
    with zipfile.ZipFile(zip_f, "w") as zf:
        zf.writestr("archive/data.pkl", b"clean_data")
        zf.writestr("archive/setup.bat", b"@echo off\nevil.exe")

    with pytest.raises(InvalidModelError) as exc_info:
        scan_model_file(zip_f)
    assert "forbidden executable script" in str(exc_info.value).lower()


def test_safety_zip_archive_malicious_internal_pickle(temp_dir: Path):
    """Verify ZIP archives containing dangerous opcodes inside member pickles are rejected."""
    zip_f = temp_dir / "evil_pickle.pt"
    with zipfile.ZipFile(zip_f, "w") as zf:
        zf.writestr("archive/data.pkl", b"cos\nsystem\n(S'malicious'tRp1.")

    with pytest.raises(InvalidModelError) as exc_info:
        scan_model_file(zip_f)
    assert "dangerous opcode" in str(exc_info.value).lower()


def test_safety_file_size_limit(temp_dir: Path):
    """Verify model files exceeding size boundaries are rejected."""
    large_f = temp_dir / "oversized.pt"
    large_f.write_bytes(b"A" * 1024)

    scanner = ModelSafetyScanner(max_file_size_bytes=512)
    with pytest.raises(ResourceExhaustionError):
        scanner.scan(large_f)


from cvif.model.safety import (
    _probe_addition_worker,
    _probe_exception_worker,
    isolated_inspect_model_file,
)


def test_subprocess_isolation_runner():
    """Verify safe subprocess runner executes clean operations and handles exceptions."""
    res = run_isolated_model_load(_probe_addition_worker, 10, 20, timeout_seconds=5.0)
    assert res == 30

    with pytest.raises(InvalidModelError) as exc_info:
        run_isolated_model_load(_probe_exception_worker, timeout_seconds=5.0)
    assert "Simulated unpickling error" in str(exc_info.value)


def test_isolated_inspect_model_file_cli(temp_dir: Path):
    """Verify isolated subprocess model inspection executes cleanly via CLI entrypoint."""
    clean_f = temp_dir / "cli_model.onnx"
    clean_f.write_bytes(b"dummy_valid_onnx_bytes_1234567890")

    res = isolated_inspect_model_file(clean_f, timeout_seconds=5.0)
    assert res.is_safe is True
    assert res.detected_format == "onnx"
