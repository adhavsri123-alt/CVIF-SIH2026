"""Inference Provenance Orchestrator coordinating all inference assurance checks."""

import time
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from cvif.analysis.inference_provenance.alteration import PostHocAlterationCheck
from cvif.analysis.inference_provenance.base import InferenceProvenanceCheck
from cvif.analysis.inference_provenance.replay import ReplayProtectionCheck
from cvif.analysis.inference_provenance.substitution import ModelSubstitutionCheck
from cvif.audit.logger import AuditLogger
from cvif.core.enums import AuditEventType, SessionStatus
from cvif.core.schemas import AnalysisSession, Finding, InferenceRecord, ProvenanceVerificationResult, utc_now
from cvif.evidence.store import EvidenceStore
from cvif.provenance.verifier import InferenceProvenanceVerifier


class InferenceProvenanceOrchestrator:
    """Orchestrates end-to-end inference provenance verification and finding synthesis."""

    def __init__(
        self,
        verifier: InferenceProvenanceVerifier,
        checks: Optional[List[InferenceProvenanceCheck]] = None,
        evidence_store: Optional[EvidenceStore] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.verifier = verifier
        self.evidence_store = evidence_store
        self.audit_logger = audit_logger

        self.checks: List[InferenceProvenanceCheck] = checks or [
            PostHocAlterationCheck(),
            ModelSubstitutionCheck(),
            ReplayProtectionCheck(),
        ]

    def verify_and_analyze(
        self,
        record: InferenceRecord,
        raw_image: Optional[Any] = None,
        registered_model_digest: Optional[str] = None,
        registered_preprocessing_hash: Optional[str] = None,
        expected_previous_record_hash: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
        operator_id: Optional[str] = None,
    ) -> AnalysisSession:
        """Run verification pipeline and return a complete AnalysisSession with all findings."""
        start_time = utc_now()
        start_mono = time.perf_counter()
        session_id = record.session_id or uuid4()

        cfg = dict(config or {})
        if raw_image is not None:
            cfg["raw_image"] = raw_image
        if registered_model_digest is not None:
            cfg["registered_model_digest"] = registered_model_digest
        if registered_preprocessing_hash is not None:
            cfg["registered_preprocessing_hash"] = registered_preprocessing_hash
        if expected_previous_record_hash is not None:
            cfg["expected_previous_record_hash"] = expected_previous_record_hash

        session = AnalysisSession(
            session_id=session_id,
            asset_id=session_id,
            status=SessionStatus.RUNNING,
            requested_analyses=[c.threat_id for c in self.checks],
            executed_analyses=[],
            skipped_analyses=[],
            start_time=start_time,
            operator_id=operator_id or "system",
        )

        if self.audit_logger is not None:
            self.audit_logger.log_event(
                event_type=AuditEventType.ANALYSIS_STARTED,
                actor=operator_id or "provenance_orchestrator",
                session_id=session_id,
                details={
                    "record_id": str(record.record_id),
                    "model_id": record.model_id,
                    "signing_key_id": record.signing_key_id,
                    "sequence_number": record.sequence_number,
                },
            )

        all_findings: List[Finding] = []

        # Run primary verifier pipeline
        verification_result: ProvenanceVerificationResult = self.verifier.verify_record(
            record=record,
            raw_image=raw_image,
            registered_model_digest=registered_model_digest,
            registered_preprocessing_hash=registered_preprocessing_hash,
            expected_previous_record_hash=expected_previous_record_hash,
            reference_time=start_time,
            enforce_replay_checks=True,
        )
        all_findings.extend(verification_result.findings)

        # Mark executed analyses
        for check in self.checks:
            if check.check_applicable(record, cfg):
                session.executed_analyses.append(check.threat_id)
            else:
                session.skipped_analyses.append({"threat_id": check.threat_id, "reason": "Not applicable"})

        end_mono = time.perf_counter()
        session.duration_ms = round((end_mono - start_mono) * 1000, 3)
        session.end_time = utc_now()
        session.status = SessionStatus.COMPLETED
        session.findings = all_findings

        if self.audit_logger is not None:
            self.audit_logger.log_event(
                event_type=AuditEventType.ANALYSIS_COMPLETED,
                actor=operator_id or "provenance_orchestrator",
                session_id=session_id,
                details={
                    "status": verification_result.status.value,
                    "disposition": verification_result.disposition.value,
                    "findings_count": len(all_findings),
                    "duration_ms": session.duration_ms,
                },
            )

        return session
