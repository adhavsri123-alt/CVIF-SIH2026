"""Deterministic narrative justification generator for Assurance Verdicts."""

from typing import Dict, List, Optional

from cvif.core.enums import Disposition
from cvif.core.schemas import Finding


def generate_assurance_narrative(
    disposition: Disposition,
    composite_risk: float,
    dimension_scores: Dict[str, float],
    veto_findings: List[Finding],
    contributing_findings: List[Finding],
    unsupported_checks: List[str],
) -> str:
    """Deterministically compose an executive narrative justification for military assurance analysts."""
    parts: List[str] = []

    # 1. Headline Disposition
    parts.append(f"DISPOSITION: {disposition.value} | Composite Risk Score: {composite_risk:.4f}")

    # 2. Veto / Quarantine Notice
    if veto_findings:
        veto_desc = ", ".join(
            f"{f.threat_id} ({f.severity.value}, conf: {f.confidence:.2f})"
            for f in sorted(veto_findings, key=lambda x: str(x.finding_id))
        )
        parts.append(f"CRITICAL VETO TRIGGERED: {len(veto_findings)} finding(s) forced immediate quarantine: [{veto_desc}].")

    # 3. Dimensional Risk Breakdown
    dim_str = ", ".join(
        f"{dim}={score:.4f}"
        for dim, score in sorted(dimension_scores.items())
    )
    parts.append(f"Dimensional Risk Profile: {dim_str}.")

    # 4. Contributing Findings Summary
    if contributing_findings:
        threat_counts: Dict[str, int] = {}
        for f in contributing_findings:
            threat_counts[f.threat_id] = threat_counts.get(f.threat_id, 0) + 1
        threat_str = ", ".join(
            f"{tid} (count={cnt})"
            for tid, cnt in sorted(threat_counts.items())
        )
        parts.append(f"Contributing Findings ({len(contributing_findings)}): [{threat_str}].")
    else:
        parts.append("Contributing Findings: None (zero threat signals detected).")

    # 5. Unsupported / Skipped Checks & Coverage
    if unsupported_checks:
        sorted_skips = sorted(unsupported_checks)
        parts.append(
            f"Verification Coverage INCOMPLETE: {len(sorted_skips)} check(s) unperformed/skipped: {sorted_skips}. "
            "Asset cannot receive ACCEPT disposition."
        )
    else:
        parts.append("Verification Coverage: COMPLETE. All requested checks executed and evaluated.")

    return " ".join(parts)
