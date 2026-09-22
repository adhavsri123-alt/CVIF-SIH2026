"""Model integrity orchestrator coordinating MT-1 to MT-4 assurance checks and audit logging."""

import time
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from cvif.analysis.model_integrity import (
    AnomalousActivationCheck,
    BackdoorBehaviorCheck,
    ModelIntegrityCheck,
    ModelModificationCheck,
    ModelSubstitutionCheck,
)
from cvif.audit.logger import AuditLogger
from cvif.core.enums import AuditEventType, SessionStatus
from cvif.core.schemas import AnalysisSession, Finding, utc_now
from cvif.evidence.store import EvidenceStore
from cvif.model.adapter import ModelAdapter
from cvif.model.battery import ReferenceBattery, ReferenceBatteryBuilder
from cvif.storage.database import DatabaseManager


class ModelIntegrityOrchestrator:
    """Coordinates execution of model integrity checks, evidence logging, and audit tracking."""

    def __init__(
        self,
        evidence_store: Optional[EvidenceStore] = None,
        audit_logger: Optional[AuditLogger] = None,
        db_manager: Optional[DatabaseManager] = None,
    ):
        self.evidence_store = evidence_store
        self.audit_logger = audit_logger
        self.db_manager = db_manager

        # Register standard model integrity checks
        self.checks: List[ModelIntegrityCheck] = [
            ModelSubstitutionCheck(),
            ModelModificationCheck(),
            BackdoorBehaviorCheck(),
            AnomalousActivationCheck(),
        ]

    def run_analysis(
        self,
        candidate_model: ModelAdapter,
        reference_model: Optional[ModelAdapter] = None,
        battery: Optional[ReferenceBattery] = None,
        session_id: Optional[UUID] = None,
        asset_id: Optional[UUID] = None,
        requested_checks: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
        operator_id: Optional[str] = None,
    ) -> AnalysisSession:
        """Run requested or all applicable model integrity checks on candidate model."""
        sess_id = session_id or uuid4()
        ass_id = asset_id or uuid4()
        start_time = utc_now()
        start_mono = time.monotonic()
        cfg = config or {}

        probe_battery = battery or ReferenceBatteryBuilder.create_synthetic_battery(
            task_type=candidate_model.get_task_type()
        )

        # Ensure asset record exists in database for foreign key constraints
        if self.db_manager and self.db_manager.get_asset(ass_id) is None:
            from cvif.core.enums import AssetStatus, AssetType
            from cvif.core.schemas import AssetRegistration, HashManifest

            path = candidate_model.model_path
            size = path.stat().st_size if path.is_file() else 1024
            ext = path.suffix.lstrip(".").lower() if path.suffix else "bin"
            self.db_manager.save_asset(
                AssetRegistration(
                    asset_id=ass_id,
                    asset_type=AssetType.MODEL,
                    format=ext,
                    hash_manifest=HashManifest(),
                    total_size_bytes=size,
                    status=AssetStatus.ANALYSING,
                    metadata={"task_type": candidate_model.get_task_type().value},
                )
            )

        # Log session start in audit trail
        if self.audit_logger:
            self.audit_logger.log_event(
                event_type=AuditEventType.ANALYSIS_STARTED,
                actor=operator_id or "model_orchestrator",
                asset_id=ass_id,
                session_id=sess_id,
                details={
                    "model_path": str(candidate_model.model_path),
                    "task_type": candidate_model.get_task_type().value,
                    "access_level": candidate_model.get_access_level().value,
                    "reference_model": str(reference_model.model_path) if reference_model else None,
                    "battery_id": str(probe_battery.battery_id),
                    "battery_hash": probe_battery.battery_hash,
                },
            )

        executed: List[str] = []
        skipped: List[Dict[str, str]] = []
        all_findings: List[Finding] = []

        for check in self.checks:
            threat_id = check.threat_id
            if requested_checks and threat_id not in requested_checks and "AUTO" not in requested_checks:
                skipped.append({"analysis_id": threat_id, "reason": "Not in requested checks"})
                continue

            if not check.check_applicable(candidate_model, reference_model, probe_battery, cfg):
                skipped.append({"analysis_id": threat_id, "reason": "Check prerequisites not met"})
                continue

            try:
                findings = check.run(
                    candidate_model=candidate_model,
                    reference_model=reference_model,
                    battery=probe_battery,
                    session_id=sess_id,
                    asset_id=ass_id,
                    evidence_store=self.evidence_store,
                    config=cfg,
                )
                executed.append(threat_id)
                all_findings.extend(findings)

                # Log each finding to audit trail
                for f in findings:
                    if self.audit_logger:
                        self.audit_logger.log_event(
                            event_type=AuditEventType.FINDING_RECORDED,
                            actor="model_orchestrator",
                            asset_id=ass_id,
                            session_id=sess_id,
                            details={
                                "threat_id": f.threat_id,
                                "severity": f.severity.value,
                                "confidence": f.confidence,
                                "title": f.title,
                            },
                        )

            except Exception as e:
                skipped.append({"analysis_id": threat_id, "reason": f"Execution error: {e}"})

        end_time = utc_now()
        duration_ms = round((time.monotonic() - start_mono) * 1000.0, 2)

        env_updates = {
            "task_type": candidate_model.get_task_type().value,
            "access_level": candidate_model.get_access_level().value,
            "battery_hash": probe_battery.battery_hash,
            "model_id": getattr(candidate_model, "model_id", None) or "candidate_model",
            "model_digest": getattr(candidate_model, "weights_digest", None),
            "reference_weights": getattr(reference_model, "model_id", None) if reference_model else None,
        }

        if self.db_manager:
            session = self.db_manager.update_session_section(
                session_id=sess_id,
                section="model",
                asset_id=ass_id,
                executed_analyses=executed,
                skipped_analyses=skipped,
                findings=all_findings,
                environment_updates=env_updates,
                operator_id=operator_id,
                status=SessionStatus.COMPLETED,
                duration_ms=duration_ms,
            )
        else:
            session = AnalysisSession(
                session_id=sess_id,
                asset_id=ass_id,
                status=SessionStatus.COMPLETED,
                requested_analyses=requested_checks or ["AUTO"],
                executed_analyses=executed,
                skipped_analyses=skipped,
                start_time=start_time,
                end_time=end_time,
                duration_ms=duration_ms,
                findings=all_findings,
                operator_id=operator_id,
                execution_environment=env_updates,
            )

        if self.audit_logger:
            self.audit_logger.log_event(
                event_type=AuditEventType.ANALYSIS_COMPLETED,
                actor=operator_id or "model_orchestrator",
                asset_id=ass_id,
                session_id=sess_id,
                details={
                    "status": session.status.value,
                    "findings_count": len(all_findings),
                    "duration_ms": duration_ms,
                },
            )

        return session
