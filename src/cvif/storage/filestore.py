"""Secure filesystem storage foundation with path-traversal protection and atomic writes."""

import os
from pathlib import Path
import tempfile
from typing import Optional, Tuple, Union

from cvif.core.exceptions import PathTraversalError, StorageError
from cvif.crypto.hashing import sha256_bytes


def safe_resolve_path(base_dir: Union[str, Path], relative_path: Union[str, Path]) -> Path:
    """Resolve a relative path under base_dir, strictly rejecting path traversal attempts."""
    base = Path(base_dir).resolve()
    # Normalize path string: remove leading slashes to prevent absolute path override in Path.joinpath
    clean_rel = str(relative_path).lstrip("/\\")
    target = (base / clean_rel).resolve()

    try:
        common = os.path.commonpath([str(base), str(target)])
    except ValueError as e:
        # On Windows, different drive letters raise ValueError
        raise PathTraversalError(
            f"Path traversal detected: path {relative_path} crosses drive or root boundaries"
        ) from e

    if common != str(base):
        raise PathTraversalError(
            f"Path traversal detected: {relative_path} resolves to {target}, which escapes {base}"
        )

    return target


class SafeFileStore:
    """Filesystem storage manager ensuring atomic operations and boundary confinement."""

    def __init__(self, base_dir: Union[str, Path]):
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def resolve(self, relative_path: Union[str, Path]) -> Path:
        """Resolve a relative path safely within the base directory."""
        return safe_resolve_path(self.base_dir, relative_path)

    def write_bytes(
        self,
        relative_path: Union[str, Path],
        data: bytes,
        atomic: bool = True,
    ) -> Path:
        """Write binary data safely. If atomic=True, writes to temp file then renames."""
        target = self.resolve(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        if not atomic:
            try:
                target.write_bytes(data)
                return target
            except OSError as e:
                raise StorageError(f"Failed to write to {target}: {e}") from e

        # Atomic write via temporary file in the same directory (ensures same filesystem)
        temp_fd, temp_path = tempfile.mkstemp(
            prefix=".tmp_cvif_",
            dir=str(target.parent),
        )
        try:
            with os.fdopen(temp_fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())

            # Atomic replace (supported on Windows on Python 3.3+)
            os.replace(temp_path, str(target))
            return target
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise StorageError(f"Atomic write failed for {target}: {e}") from e

    def write_text(
        self,
        relative_path: Union[str, Path],
        text: str,
        encoding: str = "utf-8",
        atomic: bool = True,
    ) -> Path:
        """Write string safely with atomic replacement."""
        return self.write_bytes(relative_path, text.encode(encoding), atomic=atomic)

    def read_bytes(self, relative_path: Union[str, Path]) -> bytes:
        """Read raw bytes from a stored relative path."""
        target = self.resolve(relative_path)
        if not target.is_file():
            raise StorageError(f"File not found: {target}")
        try:
            return target.read_bytes()
        except OSError as e:
            raise StorageError(f"Failed to read file {target}: {e}") from e

    def read_text(self, relative_path: Union[str, Path], encoding: str = "utf-8") -> str:
        """Read string from a stored relative path."""
        return self.read_bytes(relative_path).decode(encoding)

    def exists(self, relative_path: Union[str, Path]) -> bool:
        """Check if relative path exists within storage."""
        try:
            target = self.resolve(relative_path)
            return target.exists()
        except PathTraversalError:
            return False

    def delete(self, relative_path: Union[str, Path]) -> bool:
        """Safely delete a file."""
        target = self.resolve(relative_path)
        if not target.exists():
            return False
        try:
            if target.is_file():
                target.unlink()
                return True
            return False
        except OSError as e:
            raise StorageError(f"Failed to delete {target}: {e}") from e

    def store_content_addressed(
        self,
        data: bytes,
        extension: str = "",
    ) -> Tuple[str, Path]:
        """Store data indexed by its SHA-256 hash in objects/ab/cdef... structure."""
        digest = sha256_bytes(data)
        prefix = digest[:2]
        suffix = digest[2:]
        ext = f".{extension.lstrip('.')}" if extension else ""
        rel_path = Path("objects") / prefix / f"{suffix}{ext}"
        full_path = self.write_bytes(rel_path, data, atomic=True)
        return digest, rel_path
