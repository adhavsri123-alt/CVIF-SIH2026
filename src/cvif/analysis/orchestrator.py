"""Orchestrator executing dataset integrity analysis battery and recording sessions."""

import time
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from cvif.analysis.base import DataIntegrityCheck
from cvif.analysis.data_integrity import (
    ContributorRiskCheck,
    LabelFlippingCheck,
    NearDuplicateCheck,
    OODInsertionCheck,
    SystematicMislabellingCheck,
    TriggerInjectionCheck,
)
from cvif.audit.logger import AuditLogger
from cvif.core.enums import AuditEventType, SessionStatus
from cvif.core.schemas import AnalysisSession, Finding, UnifiedDataset, utc_now
from cvif.evidence.store import EvidenceStore
from cvif.features.base import FeatureExtractor
from cvif.features.statistical import StatisticalFeatureExtractor
from cvif.storage.database import DatabaseManager


class DatasetIntegrityOrchestrator:
    """Coordinates execution of dataset integrity checks, evidence logging, and audit tracking."""

    def __init__(
        self,
        feature_extractor: Optional[FeatureExtractor] = None,
        evidence_store: Optional[EvidenceStore] = None,
        audit_logger: Optional[AuditLogger] = None,
        db_manager: Optional[DatabaseManager] = None,
    ):
        self.feature_extractor = feature_extractor or StatisticalFeatureExtractor()
        self.evidence_store = evidence_store
        self.audit_logger = audit_logger
        self.db_manager = db_manager

        # Register standard data-integrity checks
        self.checks: List[DataIntegrityCheck] = [
            NearDuplicateCheck(),
            TriggerInjectionCheck(),
            LabelFlippingCheck(),
            SystematicMislabellingCheck(),
            OODInsertionCheck(),
        ]
        self.contributor_check = ContributorRiskCheck()

    def run_analysis(
        self,
        dataset: UnifiedDataset,
        session_id: Optional[UUID] = None,
        requested_checks: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
        operator_id: Optional[str] = None,
    ) -> AnalysisSession:
        """Run requested or applicable data integrity checks on UnifiedDataset."""
        sess_id = session_id or uuid4()
        start_time = utc_now()
        start_mono = time.monotonic()
        cfg = config or {}

        # Log session start in audit trail
        if self.audit_logger:
            self.audit_logger.log_event(
                event_type=AuditEventType.ANALYSIS_STARTED,
                actor=operator_id or "dataset_orchestrator",
                asset_id=dataset.asset_id,
                session_id=sess_id,
                details={
                    "format": dataset.format_origin,
                    "images": len(dataset.images),
                    "annotations": len(dataset.annotations),
                },
            )

        executed: List[str] = []
        skipped: List[Dict[str, str]] = []
        all_findings: List[Finding] = []

        # Execute primary sample and label checks
        for check in self.checks:
            threat_id = check.threat_id
            if requested_checks and threat_id not in requested_checks and "AUTO" not in requested_checks:
                skipped.append({"analysis_id": threat_id, "reason": "Not in requested checks"})
                continue

            if not check.check_applicable(dataset, cfg):
                skipped.append({"analysis_id": threat_id, "reason": "Insufficient samples or classes"})
                continue

            try:
                findings = check.run(
                    dataset=dataset,
                    session_id=sess_id,
                    feature_extractor=self.feature_extractor,
                    evidence_store=self.evidence_store,
                    config=cfg,
                )
                executed.append(threat_id)
                all_findings.extend(findings)

                # Log each finding to audit trail and database
                for f in findings:
                    if self.audit_logger:
                        self.audit_logger.log_event(
                            event_type=AuditEventType.FINDING_RECORDED,
                            actor="dataset_orchestrator",
                            asset_id=dataset.asset_id,
                            session_id=sess_id,
                            details={
                                "threat_id": f.threat_id,
                                "severity": f.severity.value,
                                "confidence": f.confidence,
                                "title": f.title,
                            },
                        )
                    if self.db_manager:
                        self.db_manager.save_finding(f)

            except Exception as e:
                skipped.append({"analysis_id": threat_id, "reason": f"Execution error: {e}"})

        # Run contributor aggregation if provenance is present
        if self.contributor_check.check_applicable(dataset, cfg):
            try:
                contrib_cfg = dict(cfg)
                contrib_cfg["prior_findings"] = all_findings
                contrib_findings = self.contributor_check.run(
                    dataset=dataset,
                    session_id=sess_id,
                    feature_extractor=self.feature_extractor,
                    evidence_store=self.evidence_store,
                    config=contrib_cfg,
                )
                executed.append(self.contributor_check.threat_id)
                all_findings.extend(contrib_findings)
                for f in contrib_findings:
                    if self.audit_logger:
                        self.audit_logger.log_event(
                            event_type=AuditEventType.FINDING_RECORDED,
                            actor="dataset_orchestrator",
                            asset_id=dataset.asset_id,
                            session_id=sess_id,
                            details={"threat_id": f.threat_id, "title": f.title},
                        )
                    if self.db_manager:
                        self.db_manager.save_finding(f)
            except Exception as e:
                skipped.append({"analysis_id": self.contributor_check.threat_id, "reason": str(e)})

        end_time = utc_now()
        duration_ms = round((time.monotonic() - start_mono) * 1000.0, 2)

        session = AnalysisSession(
            session_id=sess_id,
            asset_id=dataset.asset_id,
            status=SessionStatus.COMPLETED,
            requested_analyses=requested_checks or ["AUTO"],
            executed_analyses=executed,
            skipped_analyses=skipped,
            start_time=start_time,
            end_time=end_time,
            duration_ms=duration_ms,
            findings=all_findings,
            operator_id=operator_id,
            execution_environment={
                "feature_extractor": self.feature_extractor.name,
                "embedding_dim": self.feature_extractor.embedding_dim,
            },
        )

        if self.db_manager:
            self.db_manager.save_session(session)

        if self.audit_logger:
            self.audit_logger.log_event(
                event_type=AuditEventType.ANALYSIS_COMPLETED,
                actor=operator_id or "dataset_orchestrator",
                asset_id=dataset.asset_id,
                session_id=sess_id,
                details={
                    "status": session.status.value,
                    "findings_count": len(all_findings),
                    "duration_ms": duration_ms,
                },
            )

        return session
