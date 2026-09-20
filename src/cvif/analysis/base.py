"""Base interface and abstractions for CVIF data integrity analysis checks."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from cvif.core.enums import Disposition, EvidenceType, SeverityLevel
from cvif.core.schemas import EvidenceRecord, Finding, UnifiedDataset
from cvif.evidence.store import EvidenceStore
from cvif.features.base import FeatureExtractor


class DataIntegrityCheck(ABC):
    """Abstract base class for all dataset-integrity threat detection checks (DT-1 to DT-6)."""

    @property
    @abstractmethod
    def threat_id(self) -> str:
        """Identifier from Threat Taxonomy, e.g., 'DT-1', 'DT-4'."""
        raise NotImplementedError

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the integrity check."""
        raise NotImplementedError

    @property
    @abstractmethod
    def description(self) -> str:
        """Detailed description of threat and methodology."""
        raise NotImplementedError

    @abstractmethod
    def check_applicable(self, dataset: UnifiedDataset, config: Optional[Dict[str, Any]] = None) -> bool:
        """Determine if this check can execute on the provided dataset."""
        raise NotImplementedError

    @abstractmethod
    def run(
        self,
        dataset: UnifiedDataset,
        session_id: Optional[UUID] = None,
        feature_extractor: Optional[FeatureExtractor] = None,
        evidence_store: Optional[EvidenceStore] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Execute integrity analysis and return findings with linked canonical evidence."""
        raise NotImplementedError

    def create_finding(
        self,
        dataset: UnifiedDataset,
        session_id: UUID,
        severity: SeverityLevel,
        confidence: float,
        title: str,
        description: str,
        evidence_type: EvidenceType,
        narrative: str,
        methodology: str,
        metrics: Optional[Dict[str, float]] = None,
        artifacts: Optional[List[Any]] = None,
        baseline_comparison: Optional[Dict[str, Any]] = None,
        affected_assets: Optional[List[str]] = None,
        recommended_disposition: Disposition = Disposition.REVIEW,
        limitations: Optional[List[str]] = None,
        evidence_store: Optional[EvidenceStore] = None,
        reproducibility_info: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        """Helper to construct a Finding paired with a canonical EvidenceRecord."""
        finding_id = uuid4()

        evidence = EvidenceRecord(
            finding_id=finding_id,
            session_id=session_id,
            evidence_type=evidence_type,
            metrics=metrics or {},
            artifacts=artifacts,
            baseline_comparison=baseline_comparison,
            narrative=narrative,
            methodology=methodology,
            reproducibility_info=reproducibility_info or {"threat_id": self.threat_id},
        )

        if evidence_store is not None:
            evidence_store.save_evidence(evidence)

        return Finding(
            finding_id=finding_id,
            asset_id=dataset.asset_id,
            session_id=session_id,
            threat_id=self.threat_id,
            category="DATA_INTEGRITY",
            severity=severity,
            confidence=max(0.0, min(1.0, confidence)),
            title=title,
            description=description,
            evidence_ids=[evidence.evidence_id],
            affected_assets=affected_assets or [],
            recommended_disposition=recommended_disposition,
            limitations=limitations or [],
        )
