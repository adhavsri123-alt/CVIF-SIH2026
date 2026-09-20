"""Orchestrator executing distribution shift analysis battery between dataset pairs."""

from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from cvif.analysis.distribution_shift.base import DistributionShiftCheck
from cvif.analysis.distribution_shift.covariate import CovariateShiftCheck
from cvif.analysis.distribution_shift.environmental import EnvironmentalDriftCheck
from cvif.analysis.distribution_shift.manipulation import AdversarialManipulationCheck
from cvif.analysis.distribution_shift.metrics import extract_raw_pixel_bytes
from cvif.analysis.distribution_shift.semantic import SemanticShiftCheck
from cvif.audit.logger import AuditLogger
from cvif.core.enums import AuditEventType, SessionStatus
from cvif.core.schemas import (
    AnalysisSession,
    EvidenceRecord,
    Finding,
    ShiftAssessment,
    ShiftDimensionResult,
    ShiftReport,
    UnifiedDataset,
    utc_now,
)
from cvif.evidence.store import EvidenceStore
from cvif.features.base import FeatureExtractor
from cvif.features.statistical import StatisticalFeatureExtractor
from cvif.storage.database import DatabaseManager


class DistributionShiftOrchestrator:
    """Coordinates two-distribution comparative analysis across all shift dimensions (DS-1 to DS-4)."""

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

        # Register standard distribution shift battery
        self.checks: List[DistributionShiftCheck] = [
            CovariateShiftCheck(),
            SemanticShiftCheck(),
            EnvironmentalDriftCheck(),
            AdversarialManipulationCheck(),
        ]

    def _extract_features(
        self, dataset: UnifiedDataset, extractor: FeatureExtractor
    ) -> List[List[float]]:
        """Extract embeddings for all images in dataset."""
        root = Path(dataset.dataset_root)
        embeddings: List[List[float]] = []

        for img in dataset.images:
            img_path = root / img.file_path
            try:
                if img_path.is_file():
                    raw_bytes = extract_raw_pixel_bytes(img_path.read_bytes())
                    vec = extractor.extract(raw_bytes)
                else:
                    meta_bytes = f"{img.file_hash}:{img.width}x{img.height}".encode("utf-8")
                    vec = extractor.extract(meta_bytes)
                embeddings.append(vec)
            except Exception:
                meta_bytes = f"{img.file_hash}".encode("utf-8")
                embeddings.append(extractor.extract(meta_bytes))

        return embeddings

    def run_analysis(
        self,
        reference_dataset: UnifiedDataset,
        evaluation_dataset: UnifiedDataset,
        session_id: Optional[UUID] = None,
        requested_checks: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
        operator_id: Optional[str] = None,
    ) -> Tuple[ShiftReport, AnalysisSession]:
        """Execute full distribution shift battery comparing reference and evaluation populations."""
        sess_id = session_id or uuid4()
        start_time = utc_now()
        start_mono = time.monotonic()
        cfg = config or {}
        min_sample_size = int(cfg.get("min_sample_size", 15))

        # Log session initiation
        if self.audit_logger:
            self.audit_logger.log_event(
                event_type=AuditEventType.ANALYSIS_STARTED,
                actor=operator_id or "shift_orchestrator",
                asset_id=evaluation_dataset.asset_id,
                session_id=sess_id,
                details={
                    "analysis_type": "DISTRIBUTION_SHIFT",
                    "reference_asset_id": str(reference_dataset.asset_id),
                    "reference_images": len(reference_dataset.images),
                    "evaluation_images": len(evaluation_dataset.images),
                },
            )

        executed: List[str] = []
        skipped: List[Dict[str, str]] = []
        all_findings: List[Finding] = []
        dimensions: Dict[str, ShiftDimensionResult] = {}
        evidence_records: List[EvidenceRecord] = []

        # Pre-extract features once for efficiency across DS-1, DS-4
        ref_features = self._extract_features(reference_dataset, self.feature_extractor)
        eval_features = self._extract_features(evaluation_dataset, self.feature_extractor)

        for check in self.checks:
            threat_id = check.threat_id
            if requested_checks and threat_id not in requested_checks and "AUTO" not in requested_checks:
                skipped.append({"analysis_id": threat_id, "reason": "Not in requested checks"})
                continue

            if not check.check_applicable(reference_dataset, evaluation_dataset, cfg):
                skipped.append({"analysis_id": threat_id, "reason": "Insufficient samples or metadata"})
                continue

            try:
                dim_res, finding, evidence = check.run(
                    reference_dataset=reference_dataset,
                    evaluation_dataset=evaluation_dataset,
                    session_id=sess_id,
                    feature_extractor=self.feature_extractor,
                    evidence_store=self.evidence_store,
                    config=cfg,
                    reference_features=ref_features,
                    evaluation_features=eval_features,
                )
                executed.append(threat_id)
                dimensions[check.dimension_name] = dim_res

                if finding is not None:
                    all_findings.append(finding)
                    if self.audit_logger:
                        self.audit_logger.log_event(
                            event_type=AuditEventType.FINDING_RECORDED,
                            actor="shift_orchestrator",
                            asset_id=evaluation_dataset.asset_id,
                            session_id=sess_id,
                            details={
                                "threat_id": finding.threat_id,
                                "severity": finding.severity.value,
                                "confidence": finding.confidence,
                                "title": finding.title,
                            },
                        )
                    if self.db_manager:
                        self.db_manager.save_finding(finding)

                if evidence is not None:
                    evidence_records.append(evidence)

            except Exception as e:
                skipped.append({"analysis_id": threat_id, "reason": f"Execution error: {e}"})

        # Calculate overall distance
        d_cov = dimensions.get("covariate_shift", ShiftDimensionResult(detected=False, metric_value=0.0, description="")).metric_value
        d_sem = dimensions.get("semantic_shift", ShiftDimensionResult(detected=False, metric_value=0.0, description="")).metric_value
        d_env = dimensions.get("environmental_drift", ShiftDimensionResult(detected=False, metric_value=0.0, description="")).metric_value
        d_manip = dimensions.get("adversarial_manipulation", ShiftDimensionResult(detected=False, metric_value=0.0, description="")).metric_value

        overall_distance = round(0.40 * d_cov + 0.30 * d_sem + 0.20 * d_env + 0.10 * d_manip, 6)

        # Sample size sufficiency calibration
        n_ref = len(reference_dataset.images)
        n_eval = len(evaluation_dataset.images)
        is_sufficient = n_ref >= min_sample_size and n_eval >= min_sample_size

        # Forensic assessment disambiguation
        manip_detected = dimensions.get("adversarial_manipulation", ShiftDimensionResult(detected=False, metric_value=0.0, description="")).detected
        env_detected = dimensions.get("environmental_drift", ShiftDimensionResult(detected=False, metric_value=0.0, description="")).detected
        cov_detected = dimensions.get("covariate_shift", ShiftDimensionResult(detected=False, metric_value=0.0, description="")).detected

        if not is_sufficient:
            natural_drift = round(min(0.35, max(0.05, overall_distance * 0.5)), 4)
            suspicious_manip = round(min(0.35, max(0.05, d_manip * 0.5)), 4)
            reasoning = (
                f"Sample size (N_ref={n_ref}, N_eval={n_eval} < {min_sample_size}) is below the forensic threshold. "
                "Calculated metrics are informational; insufficient evidence to reliably distinguish natural operational "
                "drift from adversarial manipulation."
            )
            characterization = "INSUFFICIENT_SAMPLES"
        elif manip_detected and d_manip > 0.25:
            suspicious_manip = round(min(0.95, max(0.65, 0.50 + d_manip * 0.50)), 4)
            natural_drift = round(max(0.05, 0.35 - d_manip * 0.30), 4)
            reasoning = (
                f"Asymmetrical subpopulation shift detected (manipulation score={d_manip:.4f}). "
                "Distribution divergence is concentrated in specific subclusters rather than uniform environmental degradation. "
                "Evidence suggests selective manipulation or localized data poisoning."
            )
            characterization = "SUSPICIOUS_MANIPULATION"
        elif env_detected and d_env > 0.15:
            natural_drift = round(min(0.95, max(0.65, 0.50 + d_env * 0.45)), 4)
            suspicious_manip = round(min(0.25, max(0.05, d_manip * 0.30)), 4)
            reasoning = (
                f"Covariate shift strongly correlates with measured image quality and sensor degradation drift (W1={d_env:.4f}). "
                "Divergence is uniformly distributed across the population, indicating natural environmental, atmospheric, "
                "or camera optic variations."
            )
            characterization = "NATURAL_ENVIRONMENTAL_DRIFT"
        elif not cov_detected and overall_distance < 0.10:
            natural_drift = 0.05
            suspicious_manip = 0.05
            reasoning = (
                "Evaluation dataset matches reference baseline across feature embeddings, class priors, and "
                "sensor quality metrics. No statistically significant distribution shift detected."
            )
            characterization = "NO_SIGNIFICANT_SHIFT"
        elif cov_detected:
            natural_drift = round(min(0.80, max(0.20, d_cov * 0.7)), 4)
            suspicious_manip = round(min(0.40, max(0.05, d_manip * 0.5)), 4)
            reasoning = (
                f"Feature-space covariate shift detected (MMD/W1={d_cov:.4f}) without dominant environmental or "
                "targeted subpopulation manipulation signatures. Represents general domain shift."
            )
            characterization = "COVARIATE_DOMAIN_SHIFT"
        else:
            natural_drift = round(min(0.50, max(0.10, overall_distance)), 4)
            suspicious_manip = round(min(0.50, max(0.10, d_manip)), 4)
            reasoning = "Moderate statistical divergence observed across dataset dimensions."
            characterization = "INDETERMINATE_SHIFT"

        assessment = ShiftAssessment(
            natural_drift_likelihood=natural_drift,
            suspicious_manipulation_likelihood=suspicious_manip,
            evidence_sufficient=is_sufficient,
            reasoning=reasoning,
        )

        report = ShiftReport(
            reference_asset_id=reference_dataset.asset_id,
            evaluation_asset_id=evaluation_dataset.asset_id,
            session_id=sess_id,
            overall_distance=overall_distance,
            dimensions=dimensions,
            assessment=assessment,
            characterization=characterization,
            timestamp=utc_now(),
            schema_version="1.0",
        )

        # Persist report as immutable artifact if EvidenceStore is provided
        if self.evidence_store is not None:
            report_bytes = report.to_canonical_json().encode("utf-8")
            self.evidence_store.save_artifact(
                session_id=sess_id,
                rel_path="shift_report.json",
                data=report_bytes,
                media_type="application/json",
                description="Comprehensive Distribution Shift Evaluation Report",
            )

        end_time = utc_now()
        duration_ms = round((time.monotonic() - start_mono) * 1000.0, 2)

        session = AnalysisSession(
            session_id=sess_id,
            asset_id=evaluation_dataset.asset_id,
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
                "analysis_type": "DISTRIBUTION_SHIFT",
                "reference_asset_id": str(reference_dataset.asset_id),
                "evaluation_asset_id": str(evaluation_dataset.asset_id),
            },
        )

        if self.db_manager:
            if self.db_manager.get_asset(evaluation_dataset.asset_id) is None:
                try:
                    from cvif.core.enums import AssetType
                    from cvif.core.schemas import AssetRegistration, HashManifest

                    asset_reg = AssetRegistration(
                        asset_id=evaluation_dataset.asset_id,
                        asset_type=AssetType.DATASET,
                        format=evaluation_dataset.format_origin,
                        hash_manifest=HashManifest(),
                        total_size_bytes=sum(img.file_size_bytes for img in evaluation_dataset.images),
                    )
                    self.db_manager.save_asset(asset_reg)
                except Exception:
                    pass
            try:
                self.db_manager.save_session(session)
            except Exception:
                pass

        if self.audit_logger:
            self.audit_logger.log_event(
                event_type=AuditEventType.ANALYSIS_COMPLETED,
                actor=operator_id or "shift_orchestrator",
                asset_id=evaluation_dataset.asset_id,
                session_id=sess_id,
                details={
                    "status": session.status.value,
                    "findings_count": len(all_findings),
                    "overall_distance": overall_distance,
                    "characterization": characterization,
                    "duration_ms": duration_ms,
                },
            )

        return report, session
