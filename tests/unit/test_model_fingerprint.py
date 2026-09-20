"""Unit tests for Behavioral Fingerprinting Engine across Classification and Detection (YOLO)."""

from pathlib import Path
import pytest

from cvif.analysis.model_fingerprint import BehavioralFingerprintEngine
from cvif.core.enums import ModelTask
from cvif.core.schemas import (
    ClassificationOutput,
    DetectionOutput,
    ModelFingerprint,
    PredictionResult,
)
from cvif.model.adapter import MockModelAdapter
from cvif.model.battery import ReferenceBatteryBuilder
from cvif.utils.matching import compute_iou, hungarian_match, match_detections


def test_matching_iou_and_hungarian_assignments():
    """Verify Kuhn-Munkres matching and IoU calculation."""
    # Exact box overlap
    box_a = [0.1, 0.1, 0.5, 0.5]
    box_b = [0.1, 0.1, 0.5, 0.5]
    assert compute_iou(box_a, box_b) == 1.0

    # Disjoint boxes
    box_c = [0.6, 0.6, 0.9, 0.9]
    assert compute_iou(box_a, box_c) == 0.0

    # Hungarian assignment on cost matrix
    cost = [
        [0.1, 0.8, 0.9],
        [0.7, 0.2, 0.6],
        [0.8, 0.7, 0.05],
    ]
    matches = hungarian_match(cost)
    assert matches == [(0, 0), (1, 1), (2, 2)]

    # Non-square cost matrix (2 candidate, 3 baseline)
    cost_rect = [
        [0.1, 0.9, 0.8],
        [0.7, 0.15, 0.6],
    ]
    matches_rect = hungarian_match(cost_rect)
    assert matches_rect == [(0, 0), (1, 1)]


def test_classification_fingerprint_determinism():
    """Verify classification fingerprint produces identical vectors and zero distance on identical models."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(
        task_type=ModelTask.CLASSIFICATION,
        num_clean=6,
        num_perturbed=2,
    )
    engine = BehavioralFingerprintEngine(top_k_classes=4)

    m1 = MockModelAdapter(task=ModelTask.CLASSIFICATION)
    m2 = MockModelAdapter(task=ModelTask.CLASSIFICATION)

    fp1 = engine.compute_fingerprint(m1, battery)
    fp2 = engine.compute_fingerprint(m2, battery)

    assert isinstance(fp1, ModelFingerprint)
    assert fp1.behavioral_signature == fp2.behavioral_signature
    assert len(fp1.behavioral_signature) == 8 * 4  # 8 probes * top 4 classes

    comp = engine.compare_models(m1, m2, battery)
    assert comp["distance"] == 0.0
    assert comp["identical"] is True
    assert comp["threat_assessment"] == "VALIDATION_RESULT"


def test_classification_fingerprint_divergence():
    """Verify classification fingerprint detects prediction divergence."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(
        task_type=ModelTask.CLASSIFICATION,
        num_clean=4,
        num_perturbed=2,
    )
    engine = BehavioralFingerprintEngine()

    # Normal model (predicts class 0 with 0.95)
    m_base = MockModelAdapter(task=ModelTask.CLASSIFICATION)

    # Substituted model (predicts class 2 with 0.98)
    sub_pred = PredictionResult(
        task_type=ModelTask.CLASSIFICATION,
        classification=ClassificationOutput(
            class_id=2,
            class_name="aerial_drone",
            confidence=0.98,
            top_k=[{"class_id": 2, "class_name": "aerial_drone", "confidence": 0.98}],
        ),
    )
    m_sub = MockModelAdapter(task=ModelTask.CLASSIFICATION, mock_output=sub_pred)

    comp = engine.compare_models(m_sub, m_base, battery)
    assert comp["distance"] > 0.25
    assert comp["threat_assessment"] == "SUSPICIOUS_INDICATOR"


def test_detection_fingerprint_yolo_components():
    """Verify YOLO detection fingerprint generates 4 subvectors and compares via Hungarian matching."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(
        task_type=ModelTask.DETECTION,
        num_clean=6,
        num_perturbed=2,
    )
    engine = BehavioralFingerprintEngine()

    m_base = MockModelAdapter(task=ModelTask.DETECTION)
    fp_base = engine.compute_fingerprint(m_base, battery)

    assert fp_base.task_type == ModelTask.DETECTION
    assert "class_detection_counts" in fp_base.task_specific_metrics
    assert fp_base.task_specific_metrics["total_detections"] == 8

    # Compare identical detection models
    m_same = MockModelAdapter(task=ModelTask.DETECTION)
    comp_same = engine.compare_models(m_same, m_base, battery)
    assert comp_same["distance"] == 0.0
    assert comp_same["mean_matched_iou"] == 1.0
    assert comp_same["class_agreement_rate"] == 1.0
    assert comp_same["threat_assessment"] == "VALIDATION_RESULT"


def test_detection_fingerprint_shifted_bboxes():
    """Verify detection fingerprint captures bounding box shifts and class changes."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(
        task_type=ModelTask.DETECTION,
        num_clean=4,
        num_perturbed=2,
    )
    engine = BehavioralFingerprintEngine()

    m_base = MockModelAdapter(task=ModelTask.DETECTION)

    # Displaced bounding box model
    displaced_pred = PredictionResult(
        task_type=ModelTask.DETECTION,
        detections=[
            DetectionOutput(
                bbox=[0.4, 0.4, 0.8, 0.8],  # Shifted coordinates
                class_id=1,                 # Changed class
                class_name="civilian_car",
                confidence=0.75,
            )
        ],
    )
    m_shifted = MockModelAdapter(task=ModelTask.DETECTION, mock_output=displaced_pred)

    comp = engine.compare_models(m_shifted, m_base, battery)
    assert comp["distance"] > 0.08
    assert comp["mean_matched_iou"] < 0.5
    assert comp["class_agreement_rate"] == 0.0
