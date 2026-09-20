"""Distribution Shift Analysis module for CVIF (Phase 6).

Implements population-level distribution divergence checks (DS-1 to DS-4)
comparing reference baseline datasets with incoming evaluation datasets.
"""

from cvif.analysis.distribution_shift.base import DistributionShiftCheck
from cvif.analysis.distribution_shift.covariate import CovariateShiftCheck
from cvif.analysis.distribution_shift.environmental import EnvironmentalDriftCheck
from cvif.analysis.distribution_shift.manipulation import AdversarialManipulationCheck
from cvif.analysis.distribution_shift.orchestrator import DistributionShiftOrchestrator
from cvif.analysis.distribution_shift.semantic import SemanticShiftCheck

__all__ = [
    "DistributionShiftCheck",
    "DistributionShiftOrchestrator",
    "CovariateShiftCheck",
    "SemanticShiftCheck",
    "EnvironmentalDriftCheck",
    "AdversarialManipulationCheck",
]
