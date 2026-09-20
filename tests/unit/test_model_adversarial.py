"""Adversarial and Edge-Case Validation for Model Integrity Subsystem.

Exposes detector behavior across:
- Clean models with natural variance
- Pruned models (structural sparsity)
- Fine-tuned models (moderate behavioral drift)
- Quantized simulation models
- Diverse backdoor configurations (varying trigger positions, sizes, target classes)
- Detection backdoor variants (class-switching vs bbox-evasion)
- Access-level boundaries (BLACK_BOX vs WHITE_BOX graceful degradation)
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import pytest

from cvif.analysis.model_fingerprint import BehavioralFingerprintEngine
from cvif.analysis.model_integrity import (
    AnomalousActivationCheck,
    BackdoorBehaviorCheck,
    ModelModificationCheck,
    ModelSubstitutionCheck,
)
from cvif.core.enums import (
    BatteryDifficulty,
    Disposition,
    EvidenceType,
    ModelAccessLevel,
    ModelTask,
    SeverityLevel,
)
from cvif.core.schemas import (
    ArchitectureSummary,
    BatteryImage,
    ClassificationOutput,
    DetectionOutput,
    LayerInfo,
    ParameterStats,
    PredictionResult,
    ReferenceBattery,
)
from cvif.evidence.store import EvidenceStore
from cvif.model.adapter import MockModelAdapter
from cvif.model.battery import ReferenceBatteryBuilder


# =========================================================================
# 1. Clean Models & Natural Variance (False Positive Minimization)
# =========================================================================

def test_clean_model_natural_variance_no_false_positive():
    """Verify that a clean model with minor statistical inference jitter is not flagged as substituted or backdoored."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)

    # Reference model: baseline deterministic
    m_ref = MockModelAdapter(task=ModelTask.CLASSIFICATION, access_level=ModelAccessLevel.WHITE_BOX)

    # Candidate model: clean, but with very slight confidence jitter
    def clean_jitter_predict(img_data: Any) -> PredictionResult:
        base = m_ref.predict(img_data)
        top_k = []
        for item in base.classification.top_k:
            top_k.append(dict(item))
        top_k[0]["confidence"] = max(0.0, min(1.0, top_k[0]["confidence"] - 0.01))
        top_k[1]["confidence"] = max(0.0, min(1.0, top_k[1]["confidence"] + 0.01))
        return PredictionResult(
            task_type=ModelTask.CLASSIFICATION,
            classification=ClassificationOutput(
                class_id=base.classification.class_id,
                class_name=base.classification.class_name,
                confidence=top_k[0]["confidence"],
                top_k=top_k,
            ),
        )

    m_cand = MockModelAdapter(task=ModelTask.CLASSIFICATION, access_level=ModelAccessLevel.WHITE_BOX)
    m_cand.predict = clean_jitter_predict

    # Check 1: Substitution check
    mt1 = ModelSubstitutionCheck()
    findings_1 = mt1.run(candidate_model=m_cand, reference_model=m_ref, battery=battery)
    assert len(findings_1) == 1
    assert findings_1[0].severity == SeverityLevel.INFORMATIONAL
    assert findings_1[0].recommended_disposition == Disposition.ACCEPT

    # Check 2: Backdoor check
    mt3 = BackdoorBehaviorCheck()
    findings_3 = mt3.run(candidate_model=m_cand, reference_model=m_ref, battery=battery)
    assert len(findings_3) == 0  # No anomalous backdoor flagged


# =========================================================================
# 2. Pruned Models & Legitimate Sparsity Changes
# =========================================================================

def test_pruned_model_parameter_structural_analysis():
    """Verify that a heavily pruned model triggers MT-2 parameter difference without false positive backdoor attribution."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)

    # Unpruned reference weights
    ref_weights = {
        "conv1.weight": [[0.4, -0.2], [0.3, 0.4]],
        "conv2.weight": [[-0.05, 0.15], [0.25, -0.35]],
        "fc.weight": [[0.5, -0.5], [0.2, -0.1]],
    }
    m_ref = MockModelAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
        mock_weights=ref_weights,
    )

    # Heavily pruned candidate (75% zeros)
    pruned_weights = {
        "conv1.weight": [[0.0, 0.0], [0.0, 0.4]],
        "conv2.weight": [[0.0, 0.0], [0.25, 0.0]],
        "fc.weight": [[0.0, -0.5], [0.0, 0.0]],
    }
    m_cand = MockModelAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
        mock_weights=pruned_weights,
    )

    mt2 = ModelModificationCheck()
    findings = mt2.run(candidate_model=m_cand, reference_model=m_ref, battery=battery)

    assert len(findings) >= 1
    f_param = findings[0]
    assert f_param.severity in (SeverityLevel.MEDIUM, SeverityLevel.HIGH)
    assert any("prun" in lim.lower() or "quant" in lim.lower() or "retrain" in lim.lower() for lim in f_param.limitations)


# =========================================================================
# 3. Fine-Tuned Model (Moderate Behavioral Drift)
# =========================================================================

def test_finetuned_model_behavioral_drift():
    """Verify that a fine-tuned model (behavioral drift 0.08 <= D < 0.25) raises MT-2 behavioral divergence with appropriate calibration."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)
    m_ref = MockModelAdapter(task=ModelTask.CLASSIFICATION)

    def finetuned_predict(img_data: Any) -> PredictionResult:
        base = m_ref.predict(img_data)
        top_k = []
        for item in base.classification.top_k:
            top_k.append(dict(item))
        # Moderately shift confidence between top 2 classes to create behavioral drift (distance ~ 0.15)
        top_k[0]["confidence"] = 0.55
        top_k[1]["confidence"] = 0.38
        return PredictionResult(
            task_type=ModelTask.CLASSIFICATION,
            classification=ClassificationOutput(
                class_id=base.classification.class_id,
                class_name=base.classification.class_name,
                confidence=0.55,
                top_k=top_k,
            ),
        )

    m_cand = MockModelAdapter(task=ModelTask.CLASSIFICATION)
    m_cand.predict = finetuned_predict

    mt2 = ModelModificationCheck()
    findings = mt2.run(candidate_model=m_cand, reference_model=m_ref, battery=battery)

    drift_finding = next((f for f in findings if "Behavioral Drift" in f.title), None)
    assert drift_finding is not None
    assert drift_finding.severity == SeverityLevel.MEDIUM
    assert "fine-tuning" in str(drift_finding.limitations).lower()


# =========================================================================
# 4. Quantized / Low-Precision Simulation
# =========================================================================

def test_quantized_model_fingerprint_stability():
    """Verify that quantization noise does not cause spurious substitution alerts."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)
    m_ref = MockModelAdapter(task=ModelTask.CLASSIFICATION)

    def quantized_predict(img_data: Any) -> PredictionResult:
        base = m_ref.predict(img_data)
        top_k = []
        for item in base.classification.top_k:
            d = dict(item)
            d["confidence"] = round(d["confidence"], 2)
            top_k.append(d)
        return PredictionResult(
            task_type=ModelTask.CLASSIFICATION,
            classification=ClassificationOutput(
                class_id=base.classification.class_id,
                class_name=base.classification.class_name,
                confidence=top_k[0]["confidence"],
                top_k=top_k,
            ),
        )

    m_cand = MockModelAdapter(task=ModelTask.CLASSIFICATION)
    m_cand.predict = quantized_predict

    engine = BehavioralFingerprintEngine()
    res = engine.compare_models(m_cand, m_ref, battery)
    assert res["distance"] < 0.05  # Slight quantization delta, well below threshold


# =========================================================================
# 5. Backdoor Trigger Variations (Positions, Sizes, Targets)
# =========================================================================

@pytest.mark.parametrize("target_idx", [0, 2, 3])
def test_backdoor_detection_varying_target_classes(target_idx: int):
    """Verify backdoor detector catches triggers targeting different output classes."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)
    m_ref = MockModelAdapter(task=ModelTask.CLASSIFICATION, access_level=ModelAccessLevel.WHITE_BOX)

    m_cand = MockModelAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
        backdoor_target_class=target_idx,
    )

    mt3 = BackdoorBehaviorCheck()
    findings = mt3.run(candidate_model=m_cand, reference_model=m_ref, battery=battery)

    assert len(findings) >= 1
    f = findings[0]
    assert f.severity == SeverityLevel.HIGH
    assert f.recommended_disposition == Disposition.QUARANTINE
    target_name = m_cand.class_names[target_idx]
    assert target_name in f.title or target_name in f.description


def test_backdoor_detection_object_detection_evasion():
    """Verify object detection evasion backdoor (trigger causes model to miss/suppress detections)."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.DETECTION)
    m_ref = MockModelAdapter(task=ModelTask.DETECTION)

    m_cand = MockModelAdapter(
        task=ModelTask.DETECTION,
        backdoor_target_class=0,
    )

    mt3 = BackdoorBehaviorCheck()
    findings = mt3.run(candidate_model=m_cand, reference_model=m_ref, battery=battery)

    assert len(findings) >= 1
    assert any("Evasion" in f.title or "Drop" in f.title or "Suppression" in f.title or "Backdoor" in f.title for f in findings)


# =========================================================================
# 6. Detection Hungarian Matching with Spatial Distortion
# =========================================================================

def test_detection_hungarian_matching_with_spatial_offset():
    """Verify that Hungarian matching gracefully correlates bboxes that are slightly spatially shifted."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.DETECTION)
    m_ref = MockModelAdapter(task=ModelTask.DETECTION)

    def shifted_predict(img_data: Any) -> PredictionResult:
        base = m_ref.predict(img_data)
        shifted_dets = []
        for det in base.detections or []:
            shifted_dets.append(
                DetectionOutput(
                    bbox=[
                        min(1.0, det.bbox[0] + 0.05),
                        min(1.0, det.bbox[1] + 0.05),
                        min(1.0, det.bbox[2] + 0.05),
                        min(1.0, det.bbox[3] + 0.05),
                    ],
                    class_id=det.class_id,
                    class_name=det.class_name,
                    confidence=det.confidence,
                )
            )
        return PredictionResult(
            task_type=ModelTask.DETECTION,
            detections=shifted_dets,
        )

    m_cand = MockModelAdapter(task=ModelTask.DETECTION)
    m_cand.predict = shifted_predict

    engine = BehavioralFingerprintEngine()
    res = engine.compare_models(m_cand, m_ref, battery)
    dist = res["distance"]
    assert 0.0 < dist < 0.40


# =========================================================================
# 7. Access Level Boundary Degradation (BLACK_BOX graceful handling)
# =========================================================================

def test_black_box_model_graceful_capability_degradation():
    """Verify that black-box models gracefully return structured unsupported results for white-box checks."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)
    m_black = MockModelAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.BLACK_BOX,
    )

    # 1. Activation check returns informational finding for BLACK_BOX without crash
    mt4 = AnomalousActivationCheck()
    findings = mt4.run(candidate_model=m_black, reference_model=None, battery=battery)
    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.INFORMATIONAL
    assert "WHITE_BOX" in findings[0].title

    # 2. Adapter methods return structured empty/unsupported values or raise AccessDeniedError
    from cvif.core.exceptions import AccessDeniedError
    with pytest.raises(AccessDeniedError):
        m_black.get_weight_digest()

    with pytest.raises(AccessDeniedError):
        m_black.get_parameter_statistics()

    with pytest.raises(AccessDeniedError):
        m_black.enumerate_layers()

    # 3. Behavioral fingerprinting STILL works for BLACK_BOX
    engine = BehavioralFingerprintEngine()
    fp = engine.compute_fingerprint(m_black, battery)
    assert fp.behavioral_signature is not None
    assert len(fp.behavioral_signature) > 0
