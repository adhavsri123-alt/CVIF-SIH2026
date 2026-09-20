"""Shared runtime context and service initialization for CVIF CLI commands."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from cvif.audit.logger import AuditLogger
from cvif.core.config import AppConfig, load_config
from cvif.core.exceptions import PathTraversalError
from cvif.crypto.keystore import KeyStore
from cvif.evidence.store import EvidenceStore
from cvif.storage.database import DatabaseManager


def resolve_cli_path(path: Union[str, Path]) -> Path:
    """Validate and resolve a user-supplied CLI path, prohibiting null bytes."""
    path_str = str(path)
    if "\x00" in path_str:
        raise PathTraversalError("Path traversal detected: null byte in path")
    return Path(path).resolve()


@dataclass
class RuntimeContext:
    """Container holding instantiated CVIF services configured for the current invocation."""
    config: AppConfig
    db: DatabaseManager
    audit: AuditLogger
    evidence: EvidenceStore
    keystore: KeyStore

    def close(self) -> None:
        """Close open resources."""
        try:
            self.evidence.close()
        except Exception:
            pass
        try:
            self.db.close()
        except Exception:
            pass


def get_runtime_context(
    config_path: Optional[Union[str, Path]] = None,
    base_dir: Optional[Union[str, Path]] = None,
) -> RuntimeContext:
    """Initialize and return the central runtime services based on configuration.
    
    Ensures that paths are resolved and parent directories exist before instantiating
    database, audit, keystore, and evidence stores.
    """
    cfg = load_config(config_path)
    if base_dir:
        cfg = cfg.resolve_paths(base_dir)

    # Ensure required parent directories exist
    cfg.storage.catalog_db_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.audit.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.evidence.evidence_dir.mkdir(parents=True, exist_ok=True)
    cfg.keystore.keystore_dir.mkdir(parents=True, exist_ok=True)

    db = DatabaseManager(cfg.storage.catalog_db_path)
    audit = AuditLogger(cfg.audit.audit_log_path, auto_verify_on_init=False)
    evidence = EvidenceStore(
        base_dir=cfg.evidence.evidence_dir,
        db_manager=db,
        audit_logger=audit,
        enforce_content=True,
    )
    keystore_file = cfg.keystore.keystore_dir / "truststore.json"
    keystore = KeyStore(persistence_path=keystore_file)

    return RuntimeContext(
        config=cfg,
        db=db,
        audit=audit,
        evidence=evidence,
        keystore=keystore,
    )
