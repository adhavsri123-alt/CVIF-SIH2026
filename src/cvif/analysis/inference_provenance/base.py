"""Base interface for inference provenance analysis checks (IT-1 through IT-5)."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from cvif.core.enums import Disposition, EvidenceType, SeverityLevel
from cvif.core.schemas import EvidenceRecord, Finding, InferenceRecord
from cvif.evidence.store import EvidenceStore


class InferenceProvenanceCheck(ABC):
    """Abstract base class for inference provenance analysis checks."""

    @property
    @abstractmethod
    def threat_id(self) -> str:
        """Threat ID, e.g. 'IT-1', 'IT-2', 'IT-3', 'IT-4', 'IT-5'."""
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

    @abstractmethod
    def check_applicable(self, record: InferenceRecord, config: Optional[Dict[str, Any]] = None) -> bool:
        """Determine if this check can execute on the provided record."""
        raise NotImplementedError

    @abstractmethod
    def run(
        self,
        record: InferenceRecord,
        verifier: Any,
        session_id: Optional[UUID] = None,
        evidence_store: Optional[EvidenceStore] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Execute provenance analysis and return findings with linked canonical evidence."""
        raise NotImplementedError

    def create_finding(
        self,
        record: InferenceRecord,
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
            asset_id=record.session_id,
            session_id=session_id,
            threat_id=self.threat_id,
            category="INFERENCE_PROVENANCE",
            severity=severity,
            confidence=max(0.0, min(1.0, confidence)),
            title=title,
            description=description,
            evidence_ids=[evidence.evidence_id],
            affected_assets=affected_assets or [str(record.record_id)],
            recommended_disposition=recommended_disposition,
            limitations=limitations or ["Relies on verification against local cryptographic trust store"],
        )
