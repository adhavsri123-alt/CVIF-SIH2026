"""Analysis package for CVIF data and model integrity."""

from cvif.analysis.assurance import (
    AssuranceAggregator,
    AssuranceOrchestrator,
)
from cvif.analysis.base import DataIntegrityCheck
from cvif.analysis.data_integrity import (
    ContributorRiskCheck,
    LabelFlippingCheck,
    NearDuplicateCheck,
    OODInsertionCheck,
    SystematicMislabellingCheck,
    TriggerInjectionCheck,
)
from cvif.analysis.distribution_shift import (
    AdversarialManipulationCheck,
    CovariateShiftCheck,
    DistributionShiftCheck,
    DistributionShiftOrchestrator,
    EnvironmentalDriftCheck,
    SemanticShiftCheck,
)
from cvif.analysis.model_fingerprint import BehavioralFingerprintEngine
from cvif.analysis.model_integrity import (
    AnomalousActivationCheck,
    BackdoorBehaviorCheck,
    ModelIntegrityCheck,
    ModelModificationCheck,
    ModelSubstitutionCheck,
)
from cvif.analysis.model_orchestrator import ModelIntegrityOrchestrator
from cvif.analysis.orchestrator import DatasetIntegrityOrchestrator

__all__ = [
    # Data Integrity
    "DataIntegrityCheck",
    "DatasetIntegrityOrchestrator",
    "ContributorRiskCheck",
    "LabelFlippingCheck",
    "NearDuplicateCheck",
    "OODInsertionCheck",
    "SystematicMislabellingCheck",
    "TriggerInjectionCheck",
    # Model Integrity
    "ModelIntegrityCheck",
    "ModelIntegrityOrchestrator",
    "BehavioralFingerprintEngine",
    "ModelSubstitutionCheck",
    "ModelModificationCheck",
    "BackdoorBehaviorCheck",
    "AnomalousActivationCheck",
    # Distribution Shift
    "DistributionShiftCheck",
    "DistributionShiftOrchestrator",
    "CovariateShiftCheck",
    "SemanticShiftCheck",
    "EnvironmentalDriftCheck",
    "AdversarialManipulationCheck",
    # Assurance Aggregation
    "AssuranceAggregator",
    "AssuranceOrchestrator",
]

