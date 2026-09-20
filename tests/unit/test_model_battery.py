"""Unit tests for Reference Battery generation, hashing, persistence, and tamper verification."""

from pathlib import Path
import pytest

from cvif.core.enums import BatteryDifficulty, ModelTask
from cvif.core.exceptions import CorruptedArtifactError, StorageError
from cvif.core.schemas import ReferenceBattery
from cvif.model.battery import ReferenceBatteryBuilder


def test_synthetic_battery_generation_classification():
    """Verify synthetic reference battery creation for classification."""
    b = ReferenceBatteryBuilder.create_synthetic_battery(
        task_type=ModelTask.CLASSIFICATION,
        name="test_cls_battery",
        num_clean=6,
        num_perturbed=3,
    )
    assert isinstance(b, ReferenceBattery)
    assert b.task_type == ModelTask.CLASSIFICATION
    assert len(b.images) == 9
    assert len(b.battery_hash) == 64

    clean_count = sum(1 for img in b.images if not img.perturbation_type)
    perturbed_count = sum(1 for img in b.images if img.perturbation_type)
    assert clean_count == 6
    assert perturbed_count == 3


def test_synthetic_battery_generation_detection():
    """Verify synthetic reference battery creation for object detection."""
    b = ReferenceBatteryBuilder.create_synthetic_battery(
        task_type=ModelTask.DETECTION,
        name="test_det_battery",
        num_clean=4,
        num_perturbed=2,
    )
    assert b.task_type == ModelTask.DETECTION
    assert len(b.images) == 6
    for img in b.images:
        assert img.ground_truth_bboxes is not None
        assert len(img.ground_truth_bboxes) == 1
        bbox = img.ground_truth_bboxes[0].bbox
        assert len(bbox) == 4
        assert 0.0 <= bbox[0] <= bbox[2] <= 1.0


def test_battery_determinism_and_hashing():
    """Verify identical battery specifications produce identical cryptographic hashes."""
    b1 = ReferenceBatteryBuilder.create_synthetic_battery(
        task_type=ModelTask.CLASSIFICATION,
        name="battery_reproducibility_test",
        num_clean=5,
        num_perturbed=2,
    )
    b2 = ReferenceBatteryBuilder.create_synthetic_battery(
        task_type=ModelTask.CLASSIFICATION,
        name="battery_reproducibility_test",
        num_clean=5,
        num_perturbed=2,
    )
    assert b1.battery_hash == b2.battery_hash


def test_battery_persistence_and_loading(temp_dir: Path):
    """Verify saving and loading reference battery with cryptographic integrity checks."""
    battery_dir = temp_dir / "persisted_battery"
    b_saved = ReferenceBatteryBuilder.create_synthetic_battery(
        task_type=ModelTask.CLASSIFICATION,
        output_dir=battery_dir,
    )
    assert (battery_dir / "battery_manifest.json").is_file()

    # Load back
    b_loaded = ReferenceBatteryBuilder.load_battery(battery_dir)
    assert b_loaded.battery_hash == b_saved.battery_hash
    assert len(b_loaded.images) == len(b_saved.images)


def test_battery_tamper_detection(temp_dir: Path):
    """Verify modifying a battery image file fails integrity verification."""
    battery_dir = temp_dir / "tampered_battery"
    ReferenceBatteryBuilder.create_synthetic_battery(
        task_type=ModelTask.CLASSIFICATION,
        output_dir=battery_dir,
    )

    # Tamper with an image file
    target_img = battery_dir / "images" / "probe_clean_000.png"
    target_img.write_bytes(b"tampered_image_content")

    with pytest.raises(CorruptedArtifactError) as exc_info:
        ReferenceBatteryBuilder.load_battery(battery_dir)
    assert "digest mismatch" in str(exc_info.value).lower()
