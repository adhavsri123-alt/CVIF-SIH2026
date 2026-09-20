"""Orchestrator coordinating assurance verdict synthesis, audit logging, and persistence."""

from typing import Any, Dict, List, Optional
from uuid import UUID

from cvif.analysis.assurance.aggregator import AssuranceAggregator
from cvif.audit.logger import AuditLogger
from cvif.core.config import AssuranceConfig
from cvif.core.enums import AuditEventType
from cvif.core.schemas import AnalysisSession, AssuranceVerdict, Finding
from cvif.storage.database import DatabaseManager


class AssuranceOrchestrator:
    """Coordinates assurance aggregation, database persistence, and tamper-evident audit trail integration."""

    def __init__(
        self,
        config: Optional[AssuranceConfig] = None,
        db_manager: Optional[DatabaseManager] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.config = config or AssuranceConfig()
        self.db_manager = db_manager
        self.audit_logger = audit_logger
        self.aggregator = AssuranceAggregator(config=self.config)

    def evaluate_session(
        self,
        session: AnalysisSession,
        additional_unsupported_checks: Optional[List[str]] = None,
        operator_id: Optional[str] = None,
    ) -> AssuranceVerdict:
        """Synthesize and persist an AssuranceVerdict directly for an existing AnalysisSession."""
        actor = operator_id or session.operator_id or "assurance_orchestrator"

        # Extract skipped analyses from session
        all_unsupported = list(additional_unsupported_checks or [])

        # Ingest findings from session
        findings = list(session.findings or [])

        verdict = self.aggregator.aggregate(
            asset_id=session.asset_id,
            session_id=session.session_id,
            findings=findings,
            unsupported_checks=all_unsupported,
            skipped_analyses=session.skipped_analyses,
            executed_analyses=session.executed_analyses,
        )

        # Attach verdict to session object
        session.verdict = verdict

        # Persist to database if db_manager is available
        if self.db_manager:
            self.db_manager.save_session(session)
            self.db_manager.save_verdict(verdict)

        # Log audit trail event
        if self.audit_logger:
            self.audit_logger.log_event(
                event_type=AuditEventType.VERDICT_ISSUED,
                actor=actor,
                asset_id=verdict.asset_id,
                session_id=verdict.session_id,
                details={
                    "verdict_id": str(verdict.verdict_id),
                    "disposition": verdict.disposition.value,
                    "composite_risk_score": verdict.composite_risk_score,
                    "contributing_findings_count": len(verdict.contributing_finding_ids),
                    "unsupported_checks_count": len(verdict.unsupported_checks),
                },
            )
            self.audit_logger.log_event(
                event_type=AuditEventType.DISPOSITION_APPLIED,
                actor=actor,
                asset_id=verdict.asset_id,
                session_id=verdict.session_id,
                details={
                    "verdict_id": str(verdict.verdict_id),
                    "disposition": verdict.disposition.value,
                    "composite_risk_score": verdict.composite_risk_score,
                },
            )

        return verdict

    def evaluate_asset(
        self,
        asset_id: UUID,
        session_id: UUID,
        findings: List[Finding],
        unsupported_checks: Optional[List[str]] = None,
        skipped_analyses: Optional[List[Dict[str, Any]]] = None,
        executed_analyses: Optional[List[str]] = None,
        operator_id: Optional[str] = None,
    ) -> AssuranceVerdict:
        """Synthesize an AssuranceVerdict from arbitrary multi-phase findings list."""
        actor = operator_id or "assurance_orchestrator"

        verdict = self.aggregator.aggregate(
            asset_id=asset_id,
            session_id=session_id,
            findings=findings,
            unsupported_checks=unsupported_checks,
            skipped_analyses=skipped_analyses,
            executed_analyses=executed_analyses,
        )

        if self.db_manager:
            self.db_manager.save_verdict(verdict)

        if self.audit_logger:
            self.audit_logger.log_event(
                event_type=AuditEventType.VERDICT_ISSUED,
                actor=actor,
                asset_id=verdict.asset_id,
                session_id=verdict.session_id,
                details={
                    "verdict_id": str(verdict.verdict_id),
                    "disposition": verdict.disposition.value,
                    "composite_risk_score": verdict.composite_risk_score,
                    "contributing_findings_count": len(verdict.contributing_finding_ids),
                    "unsupported_checks_count": len(verdict.unsupported_checks),
                },
            )

        return verdict
