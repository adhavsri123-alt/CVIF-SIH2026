"""Tamper-evident JSONL audit logger with cryptographic hash-chaining."""

import json
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from cvif.core.enums import AuditEventType
from cvif.core.exceptions import CVIFAuditChainError, StorageError
from cvif.core.schemas import AuditEvent, utc_now
from cvif.crypto.chain import (
    GENESIS_PREVIOUS_HASH,
    ArchiveVerificationResult,
    ChainVerificationResult,
    verify_audit_chain,
    verify_archive_manifest,
)
from cvif.crypto.signing import sign_ed25519


class AuditLogger:
    """Thread-safe append-only audit logger enforcing monotonic SHA-256 hash chains."""

    def __init__(
        self,
        log_path: Union[str, Path],
        auto_verify_on_init: bool = True,
        archive_dir: Optional[Union[str, Path]] = None,
    ):
        self.log_path = Path(log_path).resolve()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.archive_dir = (
            Path(archive_dir).resolve()
            if archive_dir
            else self.log_path.parent / "archive"
        )
        self._lock = threading.RLock()
        self._last_event_hash: str = GENESIS_PREVIOUS_HASH
        self._next_sequence_number: int = 0

        self._recover_state(auto_verify=auto_verify_on_init)

    @property
    def last_event_hash(self) -> str:
        """Current tip of the hash chain."""
        with self._lock:
            return self._last_event_hash

    def _recover_state(self, auto_verify: bool = True) -> None:
        """Inspect existing audit log, recover chain tip, and optionally verify integrity."""
        with self._lock:
            if not self.log_path.is_file() or self.log_path.stat().st_size == 0:
                self._last_event_hash = GENESIS_PREVIOUS_HASH
                self._next_sequence_number = 0
                return

            if auto_verify:
                result = self.verify_chain(raise_on_error=True)
                if not result.is_valid:
                    raise CVIFAuditChainError(
                        f"Audit log at {self.log_path} failed integrity verification: {result.error_message}"
                    )

            # Read the last valid event to establish tip
            events = self.read_all_events()
            if events:
                self._last_event_hash = events[-1].event_hash
                self._next_sequence_number = events[-1].sequence_number + 1
            else:
                self._last_event_hash = GENESIS_PREVIOUS_HASH
                self._next_sequence_number = 0

    def log_event(
        self,
        event_type: AuditEventType,
        actor: str,
        details: Optional[Dict[str, Any]] = None,
        asset_id: Optional[Union[str, UUID]] = None,
        session_id: Optional[Union[str, UUID]] = None,
        signing_key: Optional[Any] = None,
    ) -> AuditEvent:
        """Append a new audit event with monotonic hash chain link and optional digital signature."""
        with self._lock:
            event = AuditEvent(
                sequence_number=self._next_sequence_number,
                timestamp=utc_now(),
                event_type=event_type,
                actor=actor,
                asset_id=UUID(str(asset_id)) if asset_id else None,
                session_id=UUID(str(session_id)) if session_id else None,
                details=details or {},
                previous_event_hash=self._last_event_hash,
                event_hash="",  # placeholder
            )
            self._next_sequence_number += 1

            # Compute hash over canonical payload including previous_event_hash
            event.event_hash = event.compute_hash()

            # Sign if private key provided
            if signing_key is not None:
                event.signature = sign_ed25519(signing_key, event.event_hash.encode("utf-8"))

            # Write event line canonically to JSONL
            line = event.to_canonical_json() + "\n"
            try:
                with self.log_path.open("a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
            except OSError as e:
                raise StorageError(f"Failed to append to audit log {self.log_path}: {e}") from e

            self._last_event_hash = event.event_hash
            return event

    def read_all_events(self) -> List[AuditEvent]:
        """Read and parse all audit events from the log file in sequence."""
        with self._lock:
            if not self.log_path.is_file():
                return []

            events: List[AuditEvent] = []
            try:
                with self.log_path.open("r", encoding="utf-8") as f:
                    for line_num, line in enumerate(f, 1):
                        stripped = line.strip()
                        if not stripped:
                            continue
                        try:
                            event = AuditEvent.model_validate_json(stripped)
                            events.append(event)
                        except Exception as e:
                            raise CVIFAuditChainError(
                                f"Malformed audit event JSON at line {line_num}: {e}"
                            ) from e
            except OSError as e:
                raise StorageError(f"Failed to read audit log {self.log_path}: {e}") from e

            return events

    def verify_chain(self, raise_on_error: bool = False) -> ChainVerificationResult:
        """Verify the complete hash chain from genesis to tip."""
        with self._lock:
            events = self.read_all_events()
            return verify_audit_chain(events, raise_on_error=raise_on_error)

    def verify_archive(self, raise_on_error: bool = False) -> Optional[ArchiveVerificationResult]:
        """Verify sealed historical archive against its cryptographic manifest if present."""
        archive_file = self.archive_dir / "audit_epoch_0_historical.jsonl"
        manifest_file = self.archive_dir / "epoch_0_manifest.json"

        if not archive_file.is_file() and not manifest_file.is_file():
            return None

        return verify_archive_manifest(
            archive_path=archive_file,
            manifest_path=manifest_file,
            raise_on_error=raise_on_error,
        )
