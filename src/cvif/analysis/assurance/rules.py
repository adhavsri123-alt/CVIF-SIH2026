"""Rule engine, weights, validation, and disposition logic for Assurance Aggregation."""

import math
from typing import Any, Dict, List, Optional
from uuid import UUID

from cvif.core.enums import Disposition, SeverityLevel
from cvif.core.exceptions import SchemaValidationError
from cvif.core.schemas import Finding

DEFAULT_SEVERITY_WEIGHTS: Dict[str, float] = {
    SeverityLevel.CRITICAL.value: 1.00,
    SeverityLevel.HIGH.value: 0.80,
    SeverityLevel.MEDIUM.value: 0.50,
    SeverityLevel.LOW.value: 0.20,
    SeverityLevel.INFORMATIONAL.value: 0.00,
}

DEFAULT_DIMENSION_WEIGHTS: Dict[str, float] = {
    "data_integrity": 0.25,
    "model_integrity": 0.35,
    "inference_provenance": 0.25,
    "distribution_shift": 0.15,
}

VALID_DIMENSIONS = {
    "data_integrity",
    "model_integrity",
    "inference_provenance",
    "distribution_shift",
}


def validate_finding_for_assurance(finding: Finding) -> None:
    """Validate that finding properties are well-formed and safe for arithmetic aggregation."""
    if not isinstance(finding, Finding):
        raise SchemaValidationError(f"Expected Finding instance, got {type(finding).__name__}")

    # Validate finding_id
    if not isinstance(finding.finding_id, UUID):
        try:
            UUID(str(finding.finding_id))
        except (ValueError, TypeError, AttributeError) as e:
            raise SchemaValidationError(f"Invalid finding_id {finding.finding_id}: {e}") from e

    # Validate confidence
    conf = finding.confidence
    if not isinstance(conf, (int, float)):
        raise SchemaValidationError(f"Finding {finding.finding_id} confidence must be a float, got {type(conf).__name__}")
    if math.isnan(conf) or math.isinf(conf):
        raise SchemaValidationError(f"Finding {finding.finding_id} confidence is non-finite (NaN/Inf): {conf}")
    if conf < 0.0 or conf > 1.0:
        raise SchemaValidationError(f"Finding {finding.finding_id} confidence out of bounds [0.0, 1.0]: {conf}")

    # Validate severity
    if not isinstance(finding.severity, SeverityLevel):
        try:
            SeverityLevel(finding.severity)
        except (ValueError, KeyError) as e:
            raise SchemaValidationError(f"Finding {finding.finding_id} has invalid severity: {finding.severity}") from e

    # Validate recommended_disposition
    if not isinstance(finding.recommended_disposition, Disposition):
        try:
            Disposition(finding.recommended_disposition)
        except (ValueError, KeyError) as e:
            raise SchemaValidationError(
                f"Finding {finding.finding_id} has invalid recommended_disposition: {finding.recommended_disposition}"
            ) from e


def map_finding_to_dimension(finding: Finding) -> str:
    """Map a finding deterministically to one of the four canonical assurance dimensions."""
    cat = (finding.category or "").strip().lower()

    if cat in ("data_integrity", "dataset_integrity"):
        return "data_integrity"
    if cat in ("model_integrity",):
        return "model_integrity"
    if cat in ("inference_provenance", "provenance"):
        return "inference_provenance"
    if cat in ("distribution_shift", "shift"):
        return "distribution_shift"

    # Fallback to threat_id prefix
    tid = (finding.threat_id or "").strip().upper()
    if tid.startswith("DT-"):
        return "data_integrity"
    if tid.startswith("MT-"):
        return "model_integrity"
    if tid.startswith("IT-"):
        return "inference_provenance"
    if tid.startswith("DS-"):
        return "distribution_shift"

    raise SchemaValidationError(
        f"Finding {finding.finding_id} with category '{finding.category}' and threat_id '{finding.threat_id}' "
        f"cannot be mapped to any known assurance dimension in {VALID_DIMENSIONS}."
    )


def compute_finding_risk(
    finding: Finding,
    severity_weights: Optional[Dict[str, float]] = None,
) -> float:
    """Calculate the individual finding risk r_i = w(S(f_i)) * C(f_i)."""
    validate_finding_for_assurance(finding)
    weights = severity_weights or DEFAULT_SEVERITY_WEIGHTS

    sev_key = finding.severity.value if isinstance(finding.severity, SeverityLevel) else str(finding.severity)
    weight = weights.get(sev_key, 0.0)

    if math.isnan(weight) or math.isinf(weight) or weight < 0.0:
        raise SchemaValidationError(f"Invalid severity weight for {sev_key}: {weight}")

    raw_risk = weight * float(finding.confidence)
    # Bounded mathematically in [0.0, 1.0]
    return max(0.0, min(1.0, raw_risk))


def evaluate_critical_veto(
    finding: Finding,
    min_confidence_for_veto: float = 0.50,
) -> bool:
    """Evaluate whether a finding triggers the weakest-link critical veto."""
    validate_finding_for_assurance(finding)

    # Veto condition 1: CRITICAL severity with confidence >= min_confidence_for_veto
    if finding.severity == SeverityLevel.CRITICAL and finding.confidence >= min_confidence_for_veto:
        return True

    # Veto condition 2: explicit QUARANTINE recommendation
    if finding.recommended_disposition == Disposition.QUARANTINE:
        return True

    return False


def evaluate_disposition(
    composite_risk: float,
    veto_triggered: bool,
    has_review_recommendation: bool,
    unsupported_checks: List[str],
    quarantine_threshold: float = 0.70,
    review_threshold: float = 0.30,
) -> Disposition:
    """Determine final operational disposition using audited precedence rules."""
    # 1. QUARANTINE highest-priority veto or risk >= threshold
    if veto_triggered or composite_risk >= quarantine_threshold:
        return Disposition.QUARANTINE

    # 2. REVIEW: incomplete/insufficient coverage, risk >= review threshold, or explicit review request
    if composite_risk >= review_threshold or has_review_recommendation or len(unsupported_checks) > 0:
        return Disposition.REVIEW

    # 3. ACCEPT: only when complete coverage, low risk, and clean findings
    return Disposition.ACCEPT
