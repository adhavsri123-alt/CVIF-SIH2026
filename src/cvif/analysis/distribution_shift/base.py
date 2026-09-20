"""Base interface and abstractions for CVIF distribution shift checks (DS-1 to DS-4)."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from cvif.core.enums import Disposition, EvidenceType, SeverityLevel
from cvif.core.schemas import EvidenceRecord, Finding, ShiftDimensionResult, UnifiedDataset
from cvif.evidence.store import EvidenceStore
from cvif.features.base import FeatureExtractor


class DistributionShiftCheck(ABC):
    """Abstract base class for all distribution shift checks (DS-1 to DS-4)."""

    @property
    @abstractmethod
    def threat_id(self) -> str:
        """Identifier from Threat Taxonomy, e.g., 'DS-1', 'DS-2'."""
        raise NotImplementedError

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the shift check."""
        raise NotImplementedError

    @property
    @abstractmethod
    def description(self) -> str:
        """Detailed technical description of threat and methodology."""
        raise NotImplementedError

    @property
    @abstractmethod
    def dimension_name(self) -> str:
        """Key name for ShiftReport.dimensions dictionary."""
        raise NotImplementedError

    @abstractmethod
    def check_applicable(
        self,
        reference_dataset: UnifiedDataset,
        evaluation_dataset: UnifiedDataset,
        config: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Determine if this check can execute on the provided dataset pair."""
        raise NotImplementedError

    @abstractmethod
    def run(
        self,
        reference_dataset: UnifiedDataset,
        evaluation_dataset: UnifiedDataset,
        session_id: UUID,
        feature_extractor: Optional[FeatureExtractor] = None,
        evidence_store: Optional[EvidenceStore] = None,
        config: Optional[Dict[str, Any]] = None,
        reference_features: Optional[List[List[float]]] = None,
        evaluation_features: Optional[List[List[float]]] = None,
    ) -> Tuple[ShiftDimensionResult, Optional[Finding], Optional[EvidenceRecord]]:
        """Execute distribution shift analysis and return dimension result, optional finding, and evidence."""
        raise NotImplementedError

    def create_finding(
        self,
        evaluation_dataset: UnifiedDataset,
        session_id: UUID,
        severity: SeverityLevel,
        confidence: float,
        title: str,
        description: str,
        evidence_ids: List[UUID],
        recommended_disposition: Disposition = Disposition.REVIEW,
        affected_assets: Optional[List[str]] = None,
        limitations: Optional[List[str]] = None,
    ) -> Finding:
        """Helper to construct a canonical Finding for distribution shift."""
        return Finding(
            finding_id=uuid4(),
            asset_id=evaluation_dataset.asset_id,
            session_id=session_id,
            threat_id=self.threat_id,
            category="DISTRIBUTION_SHIFT",
            severity=severity,
            confidence=max(0.0, min(1.0, confidence)),
            title=title,
            description=description,
            evidence_ids=evidence_ids,
            affected_assets=affected_assets or [],
            recommended_disposition=recommended_disposition,
            limitations=limitations or [],
        )

    def create_evidence(
        self,
        session_id: UUID,
        evidence_type: EvidenceType,
        narrative: str,
        methodology: str,
        metrics: Dict[str, float],
        baseline_comparison: Dict[str, Any],
        reproducibility_info: Optional[Dict[str, Any]] = None,
        evidence_store: Optional[EvidenceStore] = None,
    ) -> EvidenceRecord:
        """Helper to construct and optionally persist an EvidenceRecord."""
        finding_id = uuid4()
        evidence = EvidenceRecord(
            finding_id=finding_id,
            session_id=session_id,
            evidence_type=evidence_type,
            metrics=metrics,
            artifacts=[],
            baseline_comparison=baseline_comparison,
            narrative=narrative,
            methodology=methodology,
            reproducibility_info=reproducibility_info or {"threat_id": self.threat_id},
        )
        if evidence_store is not None:
            evidence_store.save_evidence(evidence)
        return evidence
