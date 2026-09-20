import os
from pathlib import Path
import socket
import sys
import pytest

# Ensure PYTHONPATH is exported so test subprocesses can locate the package
src_path = str((Path(__file__).resolve().parent.parent / "src"))
if src_path not in os.environ.get("PYTHONPATH", ""):
    os.environ["PYTHONPATH"] = (
        f"{src_path}{os.pathsep}{os.environ['PYTHONPATH']}"
        if "PYTHONPATH" in os.environ
        else src_path
    )

from cvif.core.config import AppConfig
from cvif.crypto.signing import generate_ed25519_keypair
from cvif.crypto.keystore import KeyStore
from cvif.storage.database import DatabaseManager
from cvif.storage.filestore import SafeFileStore
from cvif.evidence.store import EvidenceStore
from cvif.audit.logger import AuditLogger


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    """Provide a clean isolated temporary directory for test artifacts."""
    return tmp_path


@pytest.fixture
def config(temp_dir: Path) -> AppConfig:
    """Create test configuration isolated in temporary directory."""
    cfg = AppConfig()
    return cfg.resolve_paths(temp_dir)


@pytest.fixture
def keypair():
    """Generate fresh Ed25519 keypair for cryptographic testing."""
    return generate_ed25519_keypair()


@pytest.fixture
def keystore(temp_dir: Path) -> KeyStore:
    """Provide an isolated local trust store."""
    keys_file = temp_dir / "keys.json"
    return KeyStore(persistence_path=keys_file)


@pytest.fixture
def db_manager(temp_dir: Path) -> DatabaseManager:
    """Provide an isolated SQLite database manager."""
    db_file = temp_dir / "test_cvif.db"
    mgr = DatabaseManager(db_file)
    yield mgr
    mgr.close()


@pytest.fixture
def file_store(temp_dir: Path) -> SafeFileStore:
    """Provide an isolated safe file store."""
    return SafeFileStore(temp_dir / "filestore")


@pytest.fixture
def evidence_store(temp_dir: Path) -> EvidenceStore:
    """Provide an isolated evidence store."""
    return EvidenceStore(temp_dir / "evidence_store")


@pytest.fixture
def audit_logger(temp_dir: Path) -> AuditLogger:
    """Provide an isolated audit logger."""
    log_file = temp_dir / "audit.jsonl"
    return AuditLogger(log_file)


@pytest.fixture
def air_gap_enforcer(monkeypatch):
    """Enforce strict air-gap by prohibiting any socket connections during test execution."""
    original_socket = socket.socket

    def guarded_socket(*args, **kwargs):
        raise RuntimeError("Air-gap violation: external network socket attempt detected!")

    monkeypatch.setattr(socket, "socket", guarded_socket)
    yield


@pytest.fixture
def make_png():
    """Helper fixture to generate valid minimal PNG byte streams."""
    def _make(width: int = 100, height: int = 80, fill_byte: int = 0) -> bytes:
        import struct
        import zlib

        signature = b"\x89PNG\r\n\x1a\n"
        ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
        ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data))
        ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + ihdr_crc

        raw_scanlines = bytes([fill_byte]) * (1 + width * 3)
        compressed = zlib.compress(raw_scanlines)
        idat_crc = struct.pack(">I", zlib.crc32(b"IDAT" + compressed))
        idat = struct.pack(">I", len(compressed)) + b"IDAT" + compressed + idat_crc

        iend_crc = struct.pack(">I", zlib.crc32(b"IEND"))
        iend = struct.pack(">I", 0) + b"IEND" + iend_crc
        return signature + ihdr + idat + iend

    return _make


@pytest.fixture
def make_jpeg():
    """Helper fixture to generate valid minimal JPEG byte streams."""
    def _make(width: int = 64, height: int = 48) -> bytes:
        import struct

        soi = b"\xff\xd8"
        sof0_payload = struct.pack(">BHHB", 8, height, width, 3) + b"\x01\x11\x00\x02\x11\x00\x03\x11\x00"
        sof0_len = struct.pack(">H", len(sof0_payload) + 2)
        sof0 = b"\xff\xc0" + sof0_len + sof0_payload
        eoi = b"\xff\xd9"
        return soi + sof0 + eoi

    return _make

