"""Core mathematical engine and aggregator for Assurance Verdict synthesis."""

from datetime import datetime, timezone
import math
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from uuid import UUID, uuid4

from cvif.analysis.assurance.narrative import generate_assurance_narrative
from cvif.analysis.assurance.rules import (
    DEFAULT_DIMENSION_WEIGHTS,
    DEFAULT_SEVERITY_WEIGHTS,
    VALID_DIMENSIONS,
    compute_finding_risk,
    evaluate_critical_veto,
    evaluate_disposition,
    map_finding_to_dimension,
    validate_finding_for_assurance,
)
from cvif.core.config import AssuranceConfig
from cvif.core.enums import Disposition, SeverityLevel
from cvif.core.exceptions import SchemaValidationError
from cvif.core.schemas import AssuranceVerdict, Finding, utc_now


class AssuranceAggregator:
    """Aggregates findings and coverage across all analysis dimensions into an authoritative AssuranceVerdict."""

    def __init__(self, config: Optional[AssuranceConfig] = None) -> None:
        self.config = config or AssuranceConfig()

        # Extract and validate severity weights
        self.severity_weights = dict(self.config.severity_weights or DEFAULT_SEVERITY_WEIGHTS)

        # Extract and normalize dimension weights
        raw_dim_weights = dict(self.config.dimension_weights or DEFAULT_DIMENSION_WEIGHTS)
        total_dim_weight = sum(raw_dim_weights.values())
        if total_dim_weight <= 0.0:
            raw_dim_weights = dict(DEFAULT_DIMENSION_WEIGHTS)
            total_dim_weight = sum(raw_dim_weights.values())

        self.dimension_weights: Dict[str, float] = {
            dim: weight / total_dim_weight
            for dim, weight in raw_dim_weights.items()
        }

        self.quarantine_threshold = float(self.config.quarantine_threshold)
        self.review_threshold = float(self.config.review_threshold)
        self.min_confidence_for_veto = float(self.config.min_confidence_for_veto)
        self.critical_veto_enabled = bool(self.config.critical_veto_enabled)

    def deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings deterministically by finding_id."""
        seen_ids: Set[str] = set()
        unique: List[Finding] = []

        for f in findings:
            validate_finding_for_assurance(f)
            fid_str = str(f.finding_id)
            if fid_str not in seen_ids:
                seen_ids.add(fid_str)
                unique.append(f)

        # Sort deterministically by finding_id string for reproducible processing
        unique.sort(key=lambda x: str(x.finding_id))
        return unique

    def process_unsupported_checks(
        self,
        unsupported_checks: Optional[List[str]] = None,
        skipped_analyses: Optional[List[Dict[str, Any]]] = None,
        executed_checks: Optional[Iterable[str]] = None,
    ) -> List[str]:
        """Consolidate and sort all unsupported/skipped check identifiers, excluding any checks that were executed or have verified findings."""
        result_set: Set[str] = set()

        if unsupported_checks:
            for c in unsupported_checks:
                if isinstance(c, str) and c.strip():
                    result_set.add(c.strip())

        if skipped_analyses:
            for s in skipped_analyses:
                if isinstance(s, dict):
                    chk = s.get("analysis_id") or s.get("check_name") or s.get("threat_id")
                    if chk and isinstance(chk, str) and chk.strip():
                        result_set.add(chk.strip())
                elif isinstance(s, str) and s.strip():
                    result_set.add(s.strip())

        # Exclude any check that was actually executed or has verified findings
        if executed_checks:
            for ec in executed_checks:
                if isinstance(ec, str) and ec.strip():
                    result_set.discard(ec.strip())

        return sorted(result_set)

    def compute_dimensional_scores(
        self,
        findings: List[Finding],
    ) -> Tuple[Dict[str, float], Dict[str, List[Finding]]]:
        """Calculate dimensional risk scores using the Noisy-OR formula: R_d = 1 - PRODUCT(1 - r_i)."""
        dim_findings: Dict[str, List[Finding]] = {dim: [] for dim in VALID_DIMENSIONS}

        for f in findings:
            dim = map_finding_to_dimension(f)
            dim_findings[dim].append(f)

        dimension_scores: Dict[str, float] = {}

        for dim in sorted(VALID_DIMENSIONS):
            f_list = dim_findings[dim]
            if not f_list:
                dimension_scores[dim] = 0.0
                continue

            # Noisy-OR accumulation: 1 - PRODUCT(1 - r_i)
            prod = 1.0
            for f in f_list:
                r_i = compute_finding_risk(f, self.severity_weights)
                prod *= (1.0 - r_i)

            noisy_or_risk = max(0.0, min(1.0, 1.0 - prod))
            dimension_scores[dim] = round(noisy_or_risk, 4)

        return dimension_scores, dim_findings

    def compute_composite_risk(
        self,
        dimension_scores: Dict[str, float],
        findings: List[Finding],
        veto_triggered: bool,
    ) -> float:
        """Calculate global composite risk: R_composite = MAX(MAX(r_i), SUM(W_d * R_d))."""
        # 1. Anti-dilution individual maximum
        individual_risks = [
            compute_finding_risk(f, self.severity_weights)
            for f in findings
        ]
        max_individual_risk = max(individual_risks) if individual_risks else 0.0

        # 2. Weighted sum of dimensional Noisy-OR scores
        weighted_dim_sum = sum(
            self.dimension_weights.get(dim, 0.0) * dimension_scores.get(dim, 0.0)
            for dim in VALID_DIMENSIONS
        )

        # 3. Anti-dilution MAX combination
        composite_risk = max(max_individual_risk, weighted_dim_sum)

        # 4. Critical veto floor
        if veto_triggered:
            composite_risk = max(composite_risk, self.quarantine_threshold)

        # Clamping and precision rounding
        clamped = max(0.0, min(1.0, composite_risk))
        return round(clamped, 4)

    def aggregate(
        self,
        asset_id: UUID,
        session_id: UUID,
        findings: List[Finding],
        unsupported_checks: Optional[List[str]] = None,
        skipped_analyses: Optional[List[Dict[str, Any]]] = None,
        executed_analyses: Optional[List[str]] = None,
    ) -> AssuranceVerdict:
        """Synthesize an authoritative AssuranceVerdict from input findings and execution metadata."""
        # 1. Deduplicate findings
        unique_findings = self.deduplicate_findings(findings)

        # Collect covered checks from executed_analyses and threat IDs of unique_findings
        covered_checks: Set[str] = set()
        if executed_analyses:
            for ec in executed_analyses:
                if isinstance(ec, str) and ec.strip():
                    covered_checks.add(ec.strip())
        for f in unique_findings:
            if f.threat_id and isinstance(f.threat_id, str):
                covered_checks.add(f.threat_id.strip())

        # 2. Process incomplete/unsupported checks
        cleaned_unsupported = self.process_unsupported_checks(
            unsupported_checks=unsupported_checks,
            skipped_analyses=skipped_analyses,
            executed_checks=covered_checks,
        )

        # 3. Evaluate Critical Vetoes
        veto_findings: List[Finding] = []
        if self.critical_veto_enabled:
            for f in unique_findings:
                if evaluate_critical_veto(f, min_confidence_for_veto=self.min_confidence_for_veto):
                    veto_findings.append(f)

        veto_triggered = len(veto_findings) > 0

        # 4. Compute Dimensional Noisy-OR Scores
        dimension_scores, _ = self.compute_dimensional_scores(unique_findings)

        # 5. Compute Composite Risk Score
        composite_risk = self.compute_composite_risk(
            dimension_scores=dimension_scores,
            findings=unique_findings,
            veto_triggered=veto_triggered,
        )

        # 6. Evaluate Operational Disposition
        has_review_rec = any(
            f.recommended_disposition == Disposition.REVIEW
            for f in unique_findings
        )
        disposition = evaluate_disposition(
            composite_risk=composite_risk,
            veto_triggered=veto_triggered,
            has_review_recommendation=has_review_rec,
            unsupported_checks=cleaned_unsupported,
            quarantine_threshold=self.quarantine_threshold,
            review_threshold=self.review_threshold,
        )

        # 7. Extract Contributing Finding IDs (findings with risk > 0 or explicit disposition recommendation)
        contributing_findings: List[Finding] = []
        for f in unique_findings:
            r_i = compute_finding_risk(f, self.severity_weights)
            if r_i > 0.0 or f.recommended_disposition in (Disposition.REVIEW, Disposition.QUARANTINE):
                contributing_findings.append(f)

        contributing_ids = [f.finding_id for f in contributing_findings]
        contributing_ids.sort(key=lambda u: str(u))

        # 8. Deterministic Narrative Justification
        narrative_summary = generate_assurance_narrative(
            disposition=disposition,
            composite_risk=composite_risk,
            dimension_scores=dimension_scores,
            veto_findings=veto_findings,
            contributing_findings=contributing_findings,
            unsupported_checks=cleaned_unsupported,
        )

        # 9. Canonical AssuranceVerdict Construction
        return AssuranceVerdict(
            verdict_id=uuid4(),
            asset_id=asset_id,
            session_id=session_id,
            composite_risk_score=composite_risk,
            disposition=disposition,
            contributing_finding_ids=contributing_ids,
            summary=narrative_summary,
            unsupported_checks=cleaned_unsupported,
            timestamp=utc_now(),
            schema_version="1.0",
        )
