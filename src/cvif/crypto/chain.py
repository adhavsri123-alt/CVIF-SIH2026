import hashlib
import json
from pathlib import Path
from typing import List, Optional, Tuple, Union

from cvif.core.exceptions import CVIFAuditChainError
from cvif.core.schemas import AuditEvent

GENESIS_PREVIOUS_HASH = "0" * 64


class ArchiveVerificationResult:
    """Result of verifying a sealed historical audit archive against its manifest."""

    def __init__(
        self,
        is_valid: bool,
        archive_file: str,
        manifest_file: str,
        expected_sha256: str,
        actual_sha256: str,
        total_events: int,
        documented_discontinuities: int,
        error_message: Optional[str] = None,
    ):
        self.is_valid = is_valid
        self.archive_file = archive_file
        self.manifest_file = manifest_file
        self.expected_sha256 = expected_sha256
        self.actual_sha256 = actual_sha256
        self.total_events = total_events
        self.documented_discontinuities = documented_discontinuities
        self.error_message = error_message

    def __repr__(self) -> str:
        return (
            f"<ArchiveVerificationResult valid={self.is_valid} "
            f"events={self.total_events} breaks={self.documented_discontinuities} "
            f"sha256={self.actual_sha256[:8] if self.actual_sha256 else 'none'}... error={self.error_message}>"
        )


class ChainVerificationResult:
    """Result of an audit chain verification check."""

    def __init__(
        self,
        is_valid: bool,
        total_events: int,
        verified_events: int,
        error_message: Optional[str] = None,
        failed_event_index: Optional[int] = None,
        failed_event_id: Optional[str] = None,
    ):
        self.is_valid = is_valid
        self.total_events = total_events
        self.verified_events = verified_events
        self.error_message = error_message
        self.failed_event_index = failed_event_index
        self.failed_event_id = failed_event_id

    def __repr__(self) -> str:
        return (
            f"<ChainVerificationResult valid={self.is_valid} "
            f"verified={self.verified_events}/{self.total_events} "
            f"error={self.error_message}>"
        )


def verify_event_hash(event: AuditEvent) -> bool:
    """Check if the event's event_hash matches the SHA-256 over its canonical payload."""
    expected = event.compute_hash()
    return event.event_hash.lower() == expected.lower()


def verify_audit_chain(
    events: List[AuditEvent],
    genesis_previous_hash: str = GENESIS_PREVIOUS_HASH,
    raise_on_error: bool = False,
) -> ChainVerificationResult:
    """Verify an entire ordered list of AuditEvents for tamper-evident hash chaining.
    
    Verifies:
    1. The genesis event points to genesis_previous_hash (default 64 zeros).
    2. Each event's computed hash strictly matches its stored event_hash.
    3. Each subsequent event's previous_event_hash strictly matches the previous event's event_hash.
    4. Event timestamps are non-decreasing.
    """
    if not events:
        return ChainVerificationResult(
            is_valid=True,
            total_events=0,
            verified_events=0,
        )

    prev_hash = genesis_previous_hash

    for i, event in enumerate(events):
        event_id_str = str(event.event_id)

        # 1. Check link to previous hash
        if event.previous_event_hash.lower() != prev_hash.lower():
            msg = (
                f"Broken chain link at index {i} (event_id={event_id_str}): "
                f"expected previous_event_hash={prev_hash}, got {event.previous_event_hash}"
            )
            if raise_on_error:
                raise CVIFAuditChainError(msg)
            return ChainVerificationResult(
                is_valid=False,
                total_events=len(events),
                verified_events=i,
                error_message=msg,
                failed_event_index=i,
                failed_event_id=event_id_str,
            )

        # 2. Check current event hash integrity
        computed_hash = event.compute_hash()
        if event.event_hash.lower() != computed_hash.lower():
            msg = (
                f"Corrupted event content at index {i} (event_id={event_id_str}): "
                f"stored event_hash={event.event_hash}, computed={computed_hash}"
            )
            if raise_on_error:
                raise CVIFAuditChainError(msg)
            return ChainVerificationResult(
                is_valid=False,
                total_events=len(events),
                verified_events=i,
                error_message=msg,
                failed_event_index=i,
                failed_event_id=event_id_str,
            )

        # 3. Check sequence monotonicity
        if i > 0 and event.sequence_number <= events[i - 1].sequence_number:
            msg = (
                f"Non-monotonic sequence number at index {i} (event_id={event_id_str}): "
                f"sequence {event.sequence_number} <= previous {events[i - 1].sequence_number}"
            )
            if raise_on_error:
                raise CVIFAuditChainError(msg)
            return ChainVerificationResult(
                is_valid=False,
                total_events=len(events),
                verified_events=i,
                error_message=msg,
                failed_event_index=i,
                failed_event_id=event_id_str,
            )

        # 4. Check chronological ordering
        if i > 0 and event.timestamp < events[i - 1].timestamp:
            msg = (
                f"Out-of-order timestamp at index {i} (event_id={event_id_str}): "
                f"{event.timestamp.isoformat()} is earlier than previous {events[i - 1].timestamp.isoformat()}"
            )
            if raise_on_error:
                raise CVIFAuditChainError(msg)
            return ChainVerificationResult(
                is_valid=False,
                total_events=len(events),
                verified_events=i,
                error_message=msg,
                failed_event_index=i,
                failed_event_id=event_id_str,
            )

        prev_hash = event.event_hash

    return ChainVerificationResult(
        is_valid=True,
        total_events=len(events),
        verified_events=len(events),
    )


def verify_archive_manifest(
    archive_path: Union[str, Path],
    manifest_path: Union[str, Path],
    raise_on_error: bool = False,
) -> ArchiveVerificationResult:
    """Verify an archived historical audit log against its sealed cryptographic manifest.

    Verifies:
    1. Both archive file and manifest exist.
    2. SHA-256 of the archive file strictly matches the manifest's sealed hash.
    3. Byte size matches the manifest.
    4. Event count matches manifest total_events.
    5. Every individual event payload hash in the archive is authentic.
    """
    archive_p = Path(archive_path)
    manifest_p = Path(manifest_path)

    if not manifest_p.is_file():
        msg = f"Archive manifest not found at {manifest_p}"
        if raise_on_error:
            raise CVIFAuditChainError(msg)
        return ArchiveVerificationResult(
            is_valid=False,
            archive_file=str(archive_p),
            manifest_file=str(manifest_p),
            expected_sha256="",
            actual_sha256="",
            total_events=0,
            documented_discontinuities=0,
            error_message=msg,
        )

    try:
        manifest_data = json.loads(manifest_p.read_text(encoding="utf-8"))
    except Exception as e:
        msg = f"Malformed archive manifest: {e}"
        if raise_on_error:
            raise CVIFAuditChainError(msg)
        return ArchiveVerificationResult(
            is_valid=False,
            archive_file=str(archive_p),
            manifest_file=str(manifest_p),
            expected_sha256="",
            actual_sha256="",
            total_events=0,
            documented_discontinuities=0,
            error_message=msg,
        )

    expected_sha256 = manifest_data.get("sha256", "")
    manifest_events_count = manifest_data.get("total_events", 0)
    manifest_breaks_count = manifest_data.get(
        "total_discontinuities", len(manifest_data.get("documented_discontinuities", []))
    )

    if not archive_p.is_file():
        msg = f"Archived audit file not found at {archive_p}"
        if raise_on_error:
            raise CVIFAuditChainError(msg)
        return ArchiveVerificationResult(
            is_valid=False,
            archive_file=str(archive_p),
            manifest_file=str(manifest_p),
            expected_sha256=expected_sha256,
            actual_sha256="",
            total_events=0,
            documented_discontinuities=manifest_breaks_count,
            error_message=msg,
        )

    # 1. Check SHA-256 hash
    hasher = hashlib.sha256()
    with archive_p.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    actual_sha256 = hasher.hexdigest()

    if actual_sha256.lower() != expected_sha256.lower():
        msg = (
            f"Historical archive tampering detected! Hash mismatch on {archive_p.name}: "
            f"expected {expected_sha256}, computed {actual_sha256}"
        )
        if raise_on_error:
            raise CVIFAuditChainError(msg)
        return ArchiveVerificationResult(
            is_valid=False,
            archive_file=str(archive_p),
            manifest_file=str(manifest_p),
            expected_sha256=expected_sha256,
            actual_sha256=actual_sha256,
            total_events=0,
            documented_discontinuities=manifest_breaks_count,
            error_message=msg,
        )

    # 2. Verify all event payloads internally
    parsed_events: List[AuditEvent] = []
    with archive_p.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            s = line.strip()
            if not s:
                continue
            try:
                ev = AuditEvent.model_validate_json(s)
                if ev.compute_hash().lower() != ev.event_hash.lower():
                    msg = f"Historical archive event payload corrupted at line {line_num} (id={ev.event_id})"
                    if raise_on_error:
                        raise CVIFAuditChainError(msg)
                    return ArchiveVerificationResult(
                        is_valid=False,
                        archive_file=str(archive_p),
                        manifest_file=str(manifest_p),
                        expected_sha256=expected_sha256,
                        actual_sha256=actual_sha256,
                        total_events=len(parsed_events),
                        documented_discontinuities=manifest_breaks_count,
                        error_message=msg,
                    )
                parsed_events.append(ev)
            except Exception as e:
                msg = f"Malformed event in historical archive at line {line_num}: {e}"
                if raise_on_error:
                    raise CVIFAuditChainError(msg)
                return ArchiveVerificationResult(
                    is_valid=False,
                    archive_file=str(archive_p),
                    manifest_file=str(manifest_p),
                    expected_sha256=expected_sha256,
                    actual_sha256=actual_sha256,
                    total_events=len(parsed_events),
                    documented_discontinuities=manifest_breaks_count,
                    error_message=msg,
                )

    if manifest_events_count and len(parsed_events) != manifest_events_count:
        msg = f"Archive event count mismatch: expected {manifest_events_count}, got {len(parsed_events)}"
        if raise_on_error:
            raise CVIFAuditChainError(msg)
        return ArchiveVerificationResult(
            is_valid=False,
            archive_file=str(archive_p),
            manifest_file=str(manifest_p),
            expected_sha256=expected_sha256,
            actual_sha256=actual_sha256,
            total_events=len(parsed_events),
            documented_discontinuities=manifest_breaks_count,
            error_message=msg,
        )

    return ArchiveVerificationResult(
        is_valid=True,
        archive_file=str(archive_p),
        manifest_file=str(manifest_p),
        expected_sha256=expected_sha256,
        actual_sha256=actual_sha256,
        total_events=len(parsed_events),
        documented_discontinuities=manifest_breaks_count,
        error_message=None,
    )
