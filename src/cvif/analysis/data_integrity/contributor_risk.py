"""Contributor and source-level risk aggregation check (DT-6)."""

from collections import defaultdict
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from cvif.analysis.base import DataIntegrityCheck
from cvif.core.enums import Disposition, EvidenceType, SeverityLevel
from cvif.core.schemas import Finding, UnifiedDataset
from cvif.evidence.store import EvidenceStore
from cvif.features.base import FeatureExtractor


class ContributorRiskCheck(DataIntegrityCheck):
    """Aggregates data integrity findings by contributor provenance when metadata is present."""

    @property
    def threat_id(self) -> str:
        return "DT-6"

    @property
    def name(self) -> str:
        return "Contributor & Source Risk Attribution"

    @property
    def description(self) -> str:
        return (
            "Aggregates data integrity anomalies (DT-1 through DT-5) by explicit contributor_id "
            "and batch_id to evaluate multi-contributor pipeline integrity."
        )

    def check_applicable(self, dataset: UnifiedDataset, config: Optional[Dict[str, Any]] = None) -> bool:
        # Strictly requires explicit contributor_id; NEVER infer or invent provenance
        return dataset.contributor_id is not None

    def run(
        self,
        dataset: UnifiedDataset,
        session_id: Optional[UUID] = None,
        feature_extractor: Optional[FeatureExtractor] = None,
        evidence_store: Optional[EvidenceStore] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        sess_id = session_id or uuid4()
        cfg = config or {}
        prior_findings: List[Finding] = cfg.get("prior_findings", [])

        if not dataset.contributor_id:
            # Explicit provenance is absent: do NOT infer or invent contributor info
            return []

        # Tally findings for this contributor
        threat_counts: Dict[str, int] = defaultdict(int)
        severity_counts: Dict[str, int] = defaultdict(int)

        for f in prior_findings:
            threat_counts[f.threat_id] += 1
            severity_counts[f.severity.value] += 1

        total_issues = len(prior_findings)
        if total_issues == 0:
            return []

        # Weighted risk calculation
        weights = {
            SeverityLevel.INFORMATIONAL.value: 0.05,
            SeverityLevel.LOW.value: 0.15,
            SeverityLevel.MEDIUM.value: 0.40,
            SeverityLevel.HIGH.value: 0.75,
            SeverityLevel.CRITICAL.value: 1.0,
        }
        score = sum(severity_counts[sev] * weights.get(sev, 0.2) for sev in severity_counts)
        normalized_risk = min(1.0, score / max(1.0, len(dataset.images) * 0.1))

        finding = self.create_finding(
            dataset=dataset,
            session_id=sess_id,
            severity=SeverityLevel.HIGH if normalized_risk > 0.6 else SeverityLevel.MEDIUM,
            confidence=0.85,
            title=f"Contributor Risk Profile: {dataset.contributor_id} (Risk Score: {normalized_risk:.2f})",
            description=(
                f"Contributor '{dataset.contributor_id}' has {total_issues} associated data integrity "
                f"finding(s) across batch '{dataset.batch_id or 'default'}': {dict(threat_counts)}."
            ),
            evidence_type=EvidenceType.COMPARATIVE,
            narrative=(
                f"Aggregated {total_issues} integrity anomalies attributed to explicit contributor "
                f"'{dataset.contributor_id}'. High finding density indicates untrusted contributor "
                f"or systematic ingestion pipeline defects."
            ),
            methodology="Cross-finding contributor attribution and normalized severity weighting",
            metrics={
                "contributor_risk_score": round(normalized_risk, 3),
                "total_contributed_images": float(len(dataset.images)),
                "total_attributed_findings": float(total_issues),
            },
            artifacts=None,
            baseline_comparison={
                "contributor_id": dataset.contributor_id,
                "batch_id": dataset.batch_id,
                "threat_breakdown": dict(threat_counts),
                "severity_breakdown": dict(severity_counts),
            },
            affected_assets=[dataset.contributor_id],
            recommended_disposition=Disposition.REVIEW if normalized_risk < 0.7 else Disposition.QUARANTINE,
            limitations=[
                "Attribution relies entirely on explicit metadata; does not account for shared keys or spoofed IDs.",
                "Single-batch contributors lack longitudinal baseline history.",
            ],
            evidence_store=evidence_store,
        )

        return [finding]
