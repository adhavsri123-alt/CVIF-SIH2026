"""Regression tests for Epoch 0 archive & Epoch 1 active audit ledger remediation."""

import hashlib
import json
import tempfile
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cvif.api.main import create_app
from cvif.audit.logger import AuditLogger
from cvif.core.enums import AuditEventType
from cvif.core.schemas import AuditEvent, utc_now
from cvif.crypto.chain import (
    GENESIS_PREVIOUS_HASH,
    verify_audit_chain,
    verify_archive_manifest,
)


@pytest.fixture
def temp_audit_env():
    """Create an isolated temporary environment with Epoch 0 archive and Epoch 1 active log."""
    with tempfile.TemporaryDirectory() as td:
        base_dir = Path(td)
        audit_dir = base_dir / "data" / "audit"
        archive_dir = audit_dir / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)

        # Copy real archive & manifest
        real_archive = Path("data/audit/archive/audit_epoch_0_historical.jsonl")
        real_manifest = Path("data/audit/archive/epoch_0_manifest.json")
        shutil.copy2(real_archive, archive_dir / "audit_epoch_0_historical.jsonl")
        shutil.copy2(real_manifest, archive_dir / "epoch_0_manifest.json")

        # Copy real active log
        real_active = Path("data/audit/audit.jsonl")
        shutil.copy2(real_active, audit_dir / "audit.jsonl")

        yield audit_dir


def test_clean_epoch_1_verification_passes(temp_audit_env):
    """Clean Epoch 1 active chain passes verification."""
    logger = AuditLogger(temp_audit_env / "audit.jsonl", archive_dir=temp_audit_env / "archive")
    res = logger.verify_chain()
    assert res.is_valid is True
    assert res.total_events >= 1
    assert res.verified_events == res.total_events
    assert res.error_message is None


def test_genesis_checkpoint_binds_epoch_0_hash(temp_audit_env):
    """Genesis checkpoint in Epoch 1 correctly binds Epoch 0 archive SHA-256 hash."""
    logger = AuditLogger(temp_audit_env / "audit.jsonl", archive_dir=temp_audit_env / "archive")
    events = logger.read_all_events()
    assert len(events) >= 1

    genesis = events[0]
    assert genesis.sequence_number == 0
    assert genesis.previous_event_hash == GENESIS_PREVIOUS_HASH
    assert genesis.event_type == AuditEventType.SYSTEM_STARTED
    assert genesis.details.get("checkpoint_type") == "EPOCH_TRANSITION"
    assert genesis.details.get("epoch") == 1

    # Verify bound hash matches real archive
    archive_file = temp_audit_env / "archive" / "audit_epoch_0_historical.jsonl"
    archive_sha256 = hashlib.sha256(archive_file.read_bytes()).hexdigest()
    assert genesis.details.get("archived_epoch_0_sha256") == archive_sha256
    assert archive_sha256 == "baa7ad64d54432539b83b89fae0e885b3c1d28b34d3eaef8129048aadf2ba081"


def test_normal_new_event_append_preserves_chain(temp_audit_env):
    """Appending legitimate events produces a continuous valid chain."""
    logger = AuditLogger(temp_audit_env / "audit.jsonl", archive_dir=temp_audit_env / "archive")
    initial_events = len(logger.read_all_events())

    ev1 = logger.log_event(
        event_type=AuditEventType.CHAIN_VERIFIED,
        actor="test_runner",
        details={"step": 1},
    )
    ev2 = logger.log_event(
        event_type=AuditEventType.ANALYSIS_COMPLETED,
        actor="test_runner",
        details={"step": 2},
    )

    assert ev1.sequence_number == initial_events
    assert ev2.sequence_number == initial_events + 1
    assert ev2.previous_event_hash == ev1.event_hash

    res = logger.verify_chain()
    assert res.is_valid is True
    assert res.total_events == initial_events + 2
    assert res.verified_events == initial_events + 2


def test_modified_active_event_payload_detected(temp_audit_env):
    """Tampering with an event payload in the active chain is strictly detected."""
    active_path = temp_audit_env / "audit.jsonl"
    lines = [json.loads(line) for line in active_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    # Modify details of block 0
    lines[0]["details"]["tampered_key"] = "attacker_payload"
    active_path.write_text("\n".join(json.dumps(l) for l in lines) + "\n", encoding="utf-8")

    logger = AuditLogger(active_path, auto_verify_on_init=False, archive_dir=temp_audit_env / "archive")
    res = logger.verify_chain()
    assert res.is_valid is False
    assert res.failed_event_index == 0
    assert "Corrupted event content" in res.error_message


def test_modified_active_event_hash_detected(temp_audit_env):
    """Tampering with an event_hash in the active chain is strictly detected."""
    logger = AuditLogger(temp_audit_env / "audit.jsonl", archive_dir=temp_audit_env / "archive")
    logger.log_event(
        event_type=AuditEventType.CHAIN_VERIFIED,
        actor="worker",
        details={"ok": True},
    )

    active_path = temp_audit_env / "audit.jsonl"
    lines = [json.loads(line) for line in active_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    # Forge event_hash on block 1
    lines[1]["event_hash"] = "0" * 64
    active_path.write_text("\n".join(json.dumps(l) for l in lines) + "\n", encoding="utf-8")

    tampered_logger = AuditLogger(active_path, auto_verify_on_init=False, archive_dir=temp_audit_env / "archive")
    res = tampered_logger.verify_chain()
    assert res.is_valid is False
    assert res.failed_event_index == 1
    assert "Corrupted event content" in res.error_message


def test_broken_active_previous_hash_link_detected(temp_audit_env):
    """A broken previous_event_hash link in the active chain is strictly detected."""
    logger = AuditLogger(temp_audit_env / "audit.jsonl", archive_dir=temp_audit_env / "archive")
    logger.log_event(
        event_type=AuditEventType.CHAIN_VERIFIED,
        actor="worker",
        details={"ok": True},
    )

    active_path = temp_audit_env / "audit.jsonl"
    lines = [json.loads(line) for line in active_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    # Break link on block 1
    lines[1]["previous_event_hash"] = "f" * 64
    # Recompute its hash so payload passes self-hash check
    ev = AuditEvent.model_validate(lines[1])
    lines[1]["event_hash"] = ev.compute_hash()
    active_path.write_text("\n".join(json.dumps(l) for l in lines) + "\n", encoding="utf-8")

    tampered_logger = AuditLogger(active_path, auto_verify_on_init=False, archive_dir=temp_audit_env / "archive")
    res = tampered_logger.verify_chain()
    assert res.is_valid is False
    assert res.failed_event_index == 1
    assert "Broken chain link" in res.error_message


def test_sequence_gap_detected(temp_audit_env):
    """Sequence number anomalies or gaps in active chain are strictly detected."""
    logger = AuditLogger(temp_audit_env / "audit.jsonl", archive_dir=temp_audit_env / "archive")
    ev1 = logger.log_event(event_type=AuditEventType.CHAIN_VERIFIED, actor="w1")

    active_path = temp_audit_env / "audit.jsonl"
    lines = [json.loads(line) for line in active_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    # Force non-monotonic sequence
    lines[1]["sequence_number"] = 0
    ev = AuditEvent.model_validate(lines[1])
    lines[1]["event_hash"] = ev.compute_hash()
    active_path.write_text("\n".join(json.dumps(l) for l in lines) + "\n", encoding="utf-8")

    tampered_logger = AuditLogger(active_path, auto_verify_on_init=False, archive_dir=temp_audit_env / "archive")
    res = tampered_logger.verify_chain()
    assert res.is_valid is False
    assert res.failed_event_index == 1
    assert "Non-monotonic sequence number" in res.error_message


def test_archive_hash_unchanged_passes(temp_audit_env):
    """Sealed Epoch 0 archive passes verification when unchanged."""
    logger = AuditLogger(temp_audit_env / "audit.jsonl", archive_dir=temp_audit_env / "archive")
    res = logger.verify_archive()
    assert res is not None
    assert res.is_valid is True
    assert res.total_events == 209
    assert res.documented_discontinuities == 3
    assert res.actual_sha256 == "baa7ad64d54432539b83b89fae0e885b3c1d28b34d3eaef8129048aadf2ba081"
    assert res.expected_sha256 == res.actual_sha256
    assert res.error_message is None


def test_archive_modification_detected(temp_audit_env):
    """Any modification to the historical archive file is detected."""
    archive_file = temp_audit_env / "archive" / "audit_epoch_0_historical.jsonl"
    with open(archive_file, "a", encoding="utf-8") as f:
        f.write("tampered_appended_line\n")

    logger = AuditLogger(temp_audit_env / "audit.jsonl", archive_dir=temp_audit_env / "archive")
    res = logger.verify_archive()
    assert res is not None
    assert res.is_valid is False
    assert "Historical archive tampering detected" in res.error_message


def test_system_health_and_api_verify():
    """Live API integration test: health is HEALTHY and /audit/verify returns VALID with active + archive info."""
    app = create_app()
    with TestClient(app) as client:
        # 1. Check health
        h_res = client.get("/api/v1/health", headers={"X-API-Key": "cvif-dev-key"})
        assert h_res.status_code == 200
        health_data = h_res.json()
        assert health_data["status"] == "HEALTHY"
        assert health_data["audit_chain"]["intact"] is True
        assert health_data["audit_chain"]["active_epoch"] == 1
        assert health_data["audit_chain"]["archive"]["present"] is True
        assert health_data["audit_chain"]["archive"]["verified"] is True
        assert health_data["audit_chain"]["archive"]["total_events"] == 209
        assert health_data["audit_chain"]["archive"]["documented_discontinuities"] == 3

        # 2. Check audit verify
        v_res = client.post("/api/v1/audit/verify", headers={"X-API-Key": "cvif-dev-key"}, json={})
        assert v_res.status_code == 200
        verify_data = v_res.json()
        assert verify_data["verified"] is True
        assert verify_data["status"] == "VALID"
        assert verify_data["active_epoch"] == 1
        assert verify_data["archive"]["verified"] is True
        assert verify_data["archive"]["expected_sha256"] == "baa7ad64d54432539b83b89fae0e885b3c1d28b34d3eaef8129048aadf2ba081"
