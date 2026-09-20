"""Unit tests for ModelIntegrityOrchestrator, evidence persistence, database tracking, and audit logging."""

from pathlib import Path
import pytest

from cvif.analysis.model_orchestrator import ModelIntegrityOrchestrator
from cvif.audit.logger import AuditLogger
from cvif.core.enums import AuditEventType, ModelAccessLevel, ModelTask, SessionStatus
from cvif.core.schemas import AnalysisSession
from cvif.evidence.store import EvidenceStore
from cvif.model.adapter import MockModelAdapter
from cvif.model.battery import ReferenceBatteryBuilder
from cvif.storage.database import DatabaseManager


def test_model_orchestrator_complete_run(temp_dir: Path):
    """Verify end-to-end model integrity session execution with audit and DB tracking."""
    db_path = temp_dir / "test_cvif.db"
    db_mgr = DatabaseManager(db_path)

    audit_path = temp_dir / "audit.jsonl"
    audit_logger = AuditLogger(audit_path)

    evidence_dir = temp_dir / "evidence"
    ev_store = EvidenceStore(evidence_dir)

    orchestrator = ModelIntegrityOrchestrator(
        evidence_store=ev_store,
        audit_logger=audit_logger,
        db_manager=db_mgr,
    )

    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)
    m_cand = MockModelAdapter(task=ModelTask.CLASSIFICATION, access_level=ModelAccessLevel.WHITE_BOX)
    m_ref = MockModelAdapter(task=ModelTask.CLASSIFICATION, access_level=ModelAccessLevel.WHITE_BOX)

    session = orchestrator.run_analysis(
        candidate_model=m_cand,
        reference_model=m_ref,
        battery=battery,
        operator_id="operator_unit_alpha",
    )

    assert isinstance(session, AnalysisSession)
    assert session.status == SessionStatus.COMPLETED
    assert len(session.executed_analyses) == 4
    assert "MT-1" in session.executed_analyses
    assert "MT-2" in session.executed_analyses
    assert "MT-3" in session.executed_analyses
    assert "MT-4" in session.executed_analyses
    assert session.duration_ms is not None and session.duration_ms >= 0.0

    # 1. Verify DB persistence
    saved_session = db_mgr.get_session(session.session_id)
    assert saved_session is not None
    assert saved_session.status == SessionStatus.COMPLETED

    findings = db_mgr.get_findings_for_session(session.session_id)
    assert len(findings) == len(session.findings)

    # 2. Verify evidence persistence in EvidenceStore
    for f in findings:
        for ev_id in f.evidence_ids:
            ev_rec = ev_store.get_evidence(ev_id)
            assert ev_rec is not None
            assert ev_rec.finding_id == f.finding_id

    # 3. Verify audit log integrity and hash chain
    chain_res = audit_logger.verify_chain()
    assert chain_res.is_valid is True
    assert chain_res.total_events >= 2

    # Check for ANALYSIS_STARTED and ANALYSIS_COMPLETED events
    events = audit_logger.read_all_events()
    event_types = [e.event_type for e in events]
    assert AuditEventType.ANALYSIS_STARTED in event_types
    assert AuditEventType.ANALYSIS_COMPLETED in event_types

    db_mgr.close()


def test_model_orchestrator_selective_checks(temp_dir: Path):
    """Verify running specific requested checks (e.g. only MT-1 and MT-3)."""
    orchestrator = ModelIntegrityOrchestrator()
    m_cand = MockModelAdapter(task=ModelTask.CLASSIFICATION)

    session = orchestrator.run_analysis(
        candidate_model=m_cand,
        requested_checks=["MT-1", "MT-3"],
    )

    assert set(session.executed_analyses) == {"MT-1", "MT-3"}
    assert len(session.skipped_analyses) == 2
