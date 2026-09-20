"""Base interface for model integrity analysis checks (MT-1 through MT-4)."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from cvif.core.enums import Disposition, EvidenceType, ModelAccessLevel, SeverityLevel
from cvif.core.schemas import EvidenceRecord, Finding
from cvif.evidence.store import EvidenceStore
from cvif.model.adapter import ModelAdapter
from cvif.model.battery import ReferenceBattery


class ModelIntegrityCheck(ABC):
    """Abstract base class for model integrity threat detection checks."""

    @property
    @abstractmethod
    def threat_id(self) -> str:
        """Threat ID, e.g. 'MT-1', 'MT-2', 'MT-3', 'MT-4'."""
        raise NotImplementedError

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable check name."""
        raise NotImplementedError

    @property
    @abstractmethod
    def description(self) -> str:
        """Technical description of threat and methodology."""
        raise NotImplementedError

    @property
    def required_access_level(self) -> ModelAccessLevel:
        """Preferred model access level for full-fidelity analysis."""
        return ModelAccessLevel.WHITE_BOX

    @property
    def minimum_access_level(self) -> ModelAccessLevel:
        """Minimum access level needed to run any analysis."""
        return ModelAccessLevel.BLACK_BOX

    @abstractmethod
    def check_applicable(
        self,
        candidate_model: ModelAdapter,
        reference_model: Optional[ModelAdapter] = None,
        battery: Optional[ReferenceBattery] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Determine if this check can execute given model capabilities and inputs."""
        raise NotImplementedError

    @abstractmethod
    def run(
        self,
        candidate_model: ModelAdapter,
        reference_model: Optional[ModelAdapter] = None,
        battery: Optional[ReferenceBattery] = None,
        session_id: Optional[UUID] = None,
        asset_id: Optional[UUID] = None,
        evidence_store: Optional[EvidenceStore] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Execute model integrity analysis and return findings paired with canonical evidence."""
        raise NotImplementedError

    def create_finding(
        self,
        asset_id: UUID,
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
            asset_id=asset_id,
            session_id=session_id,
            threat_id=self.threat_id,
            category="MODEL_INTEGRITY",
            severity=severity,
            confidence=max(0.0, min(1.0, confidence)),
            title=title,
            description=description,
            evidence_ids=[evidence.evidence_id],
            affected_assets=affected_assets or [],
            recommended_disposition=recommended_disposition,
            limitations=limitations or [],
        )
