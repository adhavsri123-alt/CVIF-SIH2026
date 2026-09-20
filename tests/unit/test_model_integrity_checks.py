"""Unit tests for Model Integrity Threat Checks (MT-1 to MT-4)."""

from pathlib import Path
import pytest

from cvif.analysis.model_integrity import (
    AnomalousActivationCheck,
    BackdoorBehaviorCheck,
    ModelModificationCheck,
    ModelSubstitutionCheck,
)
from cvif.core.enums import (
    Disposition,
    EvidenceType,
    ModelAccessLevel,
    ModelTask,
    SeverityLevel,
)
from cvif.core.schemas import (
    ClassificationOutput,
    DetectionOutput,
    PredictionResult,
)
from cvif.evidence.store import EvidenceStore
from cvif.model.adapter import MockModelAdapter
from cvif.model.battery import ReferenceBatteryBuilder


# =====================================================================
# MT-1: Model Substitution Tests
# =====================================================================


def test_mt1_substitution_identical_match(temp_dir: Path):
    """Verify MT-1 reports VALIDATION_RESULT when candidate matches reference."""
    ev_store = EvidenceStore(temp_dir / "evidence")
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)

    m_cand = MockModelAdapter(task=ModelTask.CLASSIFICATION, access_level=ModelAccessLevel.WHITE_BOX)
    m_ref = MockModelAdapter(task=ModelTask.CLASSIFICATION, access_level=ModelAccessLevel.WHITE_BOX)

    check = ModelSubstitutionCheck()
    findings = check.run(m_cand, m_ref, battery=battery, evidence_store=ev_store)

    assert len(findings) == 1
    f = findings[0]
    assert f.threat_id == "MT-1"
    assert f.severity == SeverityLevel.INFORMATIONAL
    assert f.recommended_disposition == Disposition.ACCEPT
    assert "Reference Match" in f.title


def test_mt1_substitution_detected(temp_dir: Path):
    """Verify MT-1 flags SUSPICIOUS_INDICATOR when candidate behavior diverges significantly."""
    ev_store = EvidenceStore(temp_dir / "evidence")
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)

    m_ref = MockModelAdapter(task=ModelTask.CLASSIFICATION)

    # Substituted candidate predicting completely different class
    sub_pred = PredictionResult(
        task_type=ModelTask.CLASSIFICATION,
        classification=ClassificationOutput(
            class_id=3,
            class_name="radar_station",
            confidence=0.99,
            top_k=[{"class_id": 3, "class_name": "radar_station", "confidence": 0.99}],
        ),
    )
    m_cand = MockModelAdapter(task=ModelTask.CLASSIFICATION, mock_output=sub_pred)

    check = ModelSubstitutionCheck()
    findings = check.run(m_cand, m_ref, battery=battery, evidence_store=ev_store)

    assert len(findings) == 1
    f = findings[0]
    assert f.threat_id == "MT-1"
    assert f.severity == SeverityLevel.HIGH
    assert f.recommended_disposition == Disposition.QUARANTINE
    assert "Substitution Detected" in f.title


def test_mt1_substitution_no_reference(temp_dir: Path):
    """Verify MT-1 produces informational finding when reference baseline is absent."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)
    m_cand = MockModelAdapter(task=ModelTask.CLASSIFICATION)

    check = ModelSubstitutionCheck()
    findings = check.run(m_cand, reference_model=None, battery=battery)

    assert len(findings) == 1
    f = findings[0]
    assert f.threat_id == "MT-1"
    assert f.severity == SeverityLevel.INFORMATIONAL
    assert "No Reference Baseline" in f.title
    assert len(f.limitations) >= 1


# =====================================================================
# MT-2: Model Modification Tests
# =====================================================================


def test_mt2_weight_perturbation_detected(temp_dir: Path):
    """Verify MT-2 detects per-layer parameter L2 norm perturbation."""
    ev_store = EvidenceStore(temp_dir / "evidence")
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)

    m_ref = MockModelAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
        mock_weights={
            "layer1": [1.0, 1.0, 1.0, 1.0],
            "layer2": [0.5, -0.5, 0.5, -0.5],
        },
    )
    # Perturbed weights in layer1
    m_cand = MockModelAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
        mock_weights={
            "layer1": [2.5, 2.5, 2.5, 2.5],  # Modified!
            "layer2": [0.5, -0.5, 0.5, -0.5],
        },
    )

    check = ModelModificationCheck()
    findings = check.run(m_cand, m_ref, battery=battery, evidence_store=ev_store)

    assert len(findings) >= 1
    f = findings[0]
    assert f.threat_id == "MT-2"
    assert f.severity == SeverityLevel.MEDIUM
    assert "layer1" in f.affected_assets


def test_mt2_behavioral_drift_detected(temp_dir: Path):
    """Verify MT-2 detects moderate behavioral drift in detection models."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.DETECTION)
    m_ref = MockModelAdapter(task=ModelTask.DETECTION)

    # Drifted detection outputs (slightly displaced bounding box)
    drifted_pred = PredictionResult(
        task_type=ModelTask.DETECTION,
        detections=[
            DetectionOutput(
                bbox=[0.18, 0.18, 0.58, 0.58],  # Moderate displacement
                class_id=0,
                class_name="military_vehicle",
                confidence=0.82,
            )
        ],
    )
    m_cand = MockModelAdapter(task=ModelTask.DETECTION, mock_output=drifted_pred)

    check = ModelModificationCheck()
    findings = check.run(m_cand, m_ref, battery=battery)

    assert any(f.threat_id == "MT-2" for f in findings)


# =====================================================================
# MT-3: Backdoor Behavior Tests
# =====================================================================


def test_mt3_neural_cleanse_classification_backdoor():
    """Verify MT-3 detects backdoored classification model using Neural Cleanse MAD index."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)

    # 1. Clean model
    m_clean = MockModelAdapter(task=ModelTask.CLASSIFICATION, access_level=ModelAccessLevel.WHITE_BOX)
    check = BackdoorBehaviorCheck()
    findings_clean = check.run(m_clean, battery=battery)
    assert len(findings_clean) == 0

    # 2. Backdoored model targeting class 1 (civilian_car)
    m_backdoor = MockModelAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
        backdoor_target_class=1,
    )
    findings_bd = check.run(m_backdoor, battery=battery)

    assert len(findings_bd) == 1
    f = findings_bd[0]
    assert f.threat_id == "MT-3"
    assert f.severity == SeverityLevel.HIGH
    assert f.recommended_disposition == Disposition.QUARANTINE
    assert "civilian_car" in f.title


def test_mt3_detection_evasion_backdoor():
    """Verify MT-3 detects evasion backdoor on object detection models."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(
        task_type=ModelTask.DETECTION,
        num_clean=4,
        num_perturbed=4,
    )
    # Model drops target class detections under trigger patch
    m_evasion = MockModelAdapter(
        task=ModelTask.DETECTION,
        backdoor_target_class=0,
    )
    check = BackdoorBehaviorCheck()
    findings = check.run(m_evasion, battery=battery)

    assert len(findings) == 1
    f = findings[0]
    assert f.threat_id == "MT-3"
    assert f.severity == SeverityLevel.HIGH
    assert "Evasion Backdoor" in f.title


# =====================================================================
# MT-4: Anomalous Activation Patterns Tests
# =====================================================================


def test_mt4_black_box_graceful_skip():
    """Verify MT-4 produces structured informational finding when model is BLACK_BOX."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)
    m_bb = MockModelAdapter(access_level=ModelAccessLevel.BLACK_BOX)

    check = AnomalousActivationCheck()
    findings = check.run(m_bb, battery=battery)

    assert len(findings) == 1
    f = findings[0]
    assert f.threat_id == "MT-4"
    assert f.severity == SeverityLevel.INFORMATIONAL
    assert "Requires WHITE_BOX Access" in f.title


def test_mt4_dead_neuron_cluster_detected():
    """Verify MT-4 detects abnormal dead neuron ratio in intermediate layers."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)

    # Layer with 80% non-positive activations across probes
    dead_activations = {
        "conv1": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 0.8],  # 80% dead
        "conv2": [0.3, 0.5, 0.2, 0.4, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6],  # clean
    }
    m_dead = MockModelAdapter(
        access_level=ModelAccessLevel.WHITE_BOX,
        mock_activations=dead_activations,
    )

    check = AnomalousActivationCheck()
    findings = check.run(m_dead, battery=battery)

    assert len(findings) == 1
    f = findings[0]
    assert f.threat_id == "MT-4"
    assert f.severity == SeverityLevel.MEDIUM
    assert "Dead Neuron" in f.title
    assert "conv1" in f.affected_assets


def test_mt4_representation_divergence_against_reference():
    """Verify MT-4 detects intermediate representation divergence against reference model."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)

    m_ref = MockModelAdapter(
        access_level=ModelAccessLevel.WHITE_BOX,
        mock_activations={"layer1": [1.0, 0.0, 0.0, 0.0]},
    )
    # Orthogonal / divergent activation
    m_cand = MockModelAdapter(
        access_level=ModelAccessLevel.WHITE_BOX,
        mock_activations={"layer1": [0.0, 0.0, 1.0, 0.0]},
    )

    check = AnomalousActivationCheck()
    findings = check.run(m_cand, m_ref, battery=battery)

    assert any(f.threat_id == "MT-4" and "Representation Divergence" in f.title for f in findings)
