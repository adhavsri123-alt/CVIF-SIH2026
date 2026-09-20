"""Assurance Aggregation package for the CVIF architecture."""

from cvif.analysis.assurance.aggregator import AssuranceAggregator
from cvif.analysis.assurance.narrative import generate_assurance_narrative
from cvif.analysis.assurance.orchestrator import AssuranceOrchestrator
from cvif.analysis.assurance.rules import (
    DEFAULT_DIMENSION_WEIGHTS,
    DEFAULT_SEVERITY_WEIGHTS,
    compute_finding_risk,
    evaluate_critical_veto,
    evaluate_disposition,
    map_finding_to_dimension,
    validate_finding_for_assurance,
)

__all__ = [
    "AssuranceAggregator",
    "AssuranceOrchestrator",
    "generate_assurance_narrative",
    "compute_finding_risk",
    "evaluate_critical_veto",
    "evaluate_disposition",
    "map_finding_to_dimension",
    "validate_finding_for_assurance",
    "DEFAULT_SEVERITY_WEIGHTS",
    "DEFAULT_DIMENSION_WEIGHTS",
]
