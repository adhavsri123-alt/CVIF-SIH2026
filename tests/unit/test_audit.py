"""Unit tests proving tamper-evidence and chain integrity of CVIF AuditLogger."""

from pathlib import Path
import pytest
from uuid import uuid4

from cvif.audit.logger import AuditLogger
from cvif.core.enums import AuditEventType
from cvif.core.exceptions import CVIFAuditChainError
from cvif.crypto.chain import verify_audit_chain
from cvif.crypto.signing import generate_ed25519_keypair


def test_valid_audit_chain_verifies(temp_dir: Path):
    log_file = temp_dir / "valid_audit.jsonl"
    logger = AuditLogger(log_file)

    # Log several events
    priv_key, pub_key = generate_ed25519_keypair()
    ev1 = logger.log_event(
        event_type=AuditEventType.SYSTEM_STARTED,
        actor="daemon",
        details={"mode": "air_gapped"},
        signing_key=priv_key,
    )
    ev2 = logger.log_event(
        event_type=AuditEventType.ASSET_INGESTED,
        actor="operator_1",
        asset_id=uuid4(),
        details={"format": "coco"},
    )
    ev3 = logger.log_event(
        event_type=AuditEventType.ANALYSIS_STARTED,
        actor="engine",
        session_id=uuid4(),
        details={"checks": ["trigger_injection", "near_duplicate"]},
    )

    # Verification passes
    result = logger.verify_chain()
    assert result.is_valid is True
    assert result.total_events == 3
    assert result.verified_events == 3
    assert result.error_message is None

    # Assert hash linkage
    assert ev1.previous_event_hash == "0" * 64
    assert ev2.previous_event_hash == ev1.event_hash
    assert ev3.previous_event_hash == ev2.event_hash


def test_modifying_event_breaks_verification(temp_dir: Path):
    log_file = temp_dir / "tampered_event.jsonl"
    logger = AuditLogger(log_file)

    logger.log_event(AuditEventType.SYSTEM_STARTED, actor="sys")
    logger.log_event(AuditEventType.CONFIG_CHANGED, actor="admin", details={"param": "safe"})
    logger.log_event(AuditEventType.ANALYSIS_COMPLETED, actor="engine")

    # Tamper with event 2 in the file
    content = log_file.read_text(encoding="utf-8").splitlines()
    tampered_line = content[1].replace('"safe"', '"MALICIOUS_OVERRIDE"')
    content[1] = tampered_line
    log_file.write_text("\n".join(content) + "\n", encoding="utf-8")

    # Verification must fail
    logger2 = AuditLogger(log_file, auto_verify_on_init=False)
    result = logger2.verify_chain()
    assert result.is_valid is False
    assert result.failed_event_index == 1
    assert "Corrupted event content" in result.error_message

    # Must raise CVIFAuditChainError if requested
    with pytest.raises(CVIFAuditChainError):
        logger2.verify_chain(raise_on_error=True)


def test_reordering_events_detected(temp_dir: Path):
    log_file = temp_dir / "reordered.jsonl"
    logger = AuditLogger(log_file)

    logger.log_event(AuditEventType.SYSTEM_STARTED, actor="sys")
    logger.log_event(AuditEventType.ASSET_INGESTED, actor="user", details={"step": 1})
    logger.log_event(AuditEventType.ANALYSIS_STARTED, actor="user", details={"step": 2})

    events = logger.read_all_events()
    # Swap event 1 and event 2
    swapped = [events[0], events[2], events[1]]

    result = verify_audit_chain(swapped)
    assert result.is_valid is False
    assert result.failed_event_index == 1
    assert "Broken chain link" in result.error_message


def test_deleting_event_detected(temp_dir: Path):
    log_file = temp_dir / "deleted_event.jsonl"
    logger = AuditLogger(log_file)

    logger.log_event(AuditEventType.SYSTEM_STARTED, actor="sys")
    logger.log_event(AuditEventType.ASSET_INGESTED, actor="user", details={"step": 1})
    logger.log_event(AuditEventType.ANALYSIS_STARTED, actor="user", details={"step": 2})

    events = logger.read_all_events()
    # Remove the middle event
    truncated = [events[0], events[2]]

    result = verify_audit_chain(truncated)
    assert result.is_valid is False
    assert result.failed_event_index == 1
    assert "Broken chain link" in result.error_message


def test_appending_unauthorized_modification_detected(temp_dir: Path):
    log_file = temp_dir / "unauthorized_append.jsonl"
    logger = AuditLogger(log_file)

    logger.log_event(AuditEventType.SYSTEM_STARTED, actor="sys")
    events = logger.read_all_events()

    # Create a bogus event with an incorrect previous_event_hash
    bogus_event = events[0].model_copy(deep=True)
    bogus_event.previous_event_hash = "deadbeef" * 8
    bogus_event.event_hash = bogus_event.compute_hash()

    events.append(bogus_event)
    result = verify_audit_chain(events)
    assert result.is_valid is False
    assert result.failed_event_index == 1
    assert "Broken chain link" in result.error_message
