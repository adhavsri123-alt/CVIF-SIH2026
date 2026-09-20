"""Unit tests for COCO dataset ingestion adapter and validation rules."""

import json
from pathlib import Path
import pytest

from cvif.core.exceptions import CVIFFormatError, CVIFStorageError
from cvif.core.schemas import UnifiedDataset, ValidationResult
from cvif.ingestion.adapters.coco import COCOAdapter
from cvif.ingestion.format_detector import FormatDetector
from cvif.analysis.orchestrator import DatasetIntegrityOrchestrator


def test_coco_valid_ingestion(temp_dir: Path, make_png):
    """Test standard valid COCO dataset ingestion with categories, images, and annotations."""
    ds_dir = temp_dir / "valid_coco"
    ds_dir.mkdir()
    images_dir = ds_dir / "images"
    images_dir.mkdir()

    # Create 2 valid PNG images
    (images_dir / "img1.png").write_bytes(make_png(width=200, height=100))
    (images_dir / "img2.png").write_bytes(make_png(width=400, height=300))

    coco_data = {
        "info": {
            "description": "Test COCO Dataset",
            "contributor": "Unit_Alpha_DGIS",
        },
        "categories": [
            {"id": 1, "name": "military_vehicle"},
            {"id": 2, "name": "civilian_vehicle"},
        ],
        "images": [
            {"id": 101, "file_name": "images/img1.png", "width": 200, "height": 100},
            {"id": 102, "file_name": "images/img2.png", "width": 400, "height": 300},
        ],
        "annotations": [
            {
                "id": 1001,
                "image_id": 101,
                "category_id": 1,
                "bbox": [20, 10, 80, 40],  # [x, y, w, h]
                "area": 3200.0,
                "iscrowd": 0,
            },
            {
                "id": 1002,
                "image_id": 102,
                "category_id": 2,
                "bbox": [50, 60, 100, 120],
                "area": 12000.0,
                "iscrowd": 0,
            },
        ],
    }

    ann_file = ds_dir / "instances_train.json"
    ann_file.write_text(json.dumps(coco_data), encoding="utf-8")

    adapter = COCOAdapter(ds_dir, annotation_file=ann_file)
    assert adapter.format_name == "coco"

    # Validation check
    val = adapter.validate()
    assert val.is_valid is True
    assert len(val.errors) == 0
    assert val.total_samples == 2

    # Load into UnifiedDataset
    unified = adapter.load()
    assert isinstance(unified, UnifiedDataset)
    assert unified.format_origin == "coco"
    assert len(unified.images) == 2
    assert len(unified.annotations) == 2
    assert len(unified.classes) == 2
    assert unified.contributor_id == "Unit_Alpha_DGIS"
    assert len(unified.dataset_hash) == 64

    # Check normalized bounding boxes [x_min, y_min, x_max, y_max] in [0, 1]
    ann1 = next(a for a in unified.annotations if a.annotation_id == "1001")
    assert ann1.class_name == "military_vehicle"
    assert ann1.bbox is not None
    # x: 20/200=0.1, y: 10/100=0.1, x_max: 100/200=0.5, y_max: 50/100=0.5
    assert pytest.approx(ann1.bbox[0], 0.01) == 0.1
    assert pytest.approx(ann1.bbox[1], 0.01) == 0.1
    assert pytest.approx(ann1.bbox[2], 0.01) == 0.5
    assert pytest.approx(ann1.bbox[3], 0.01) == 0.5

    # Check sample fetch
    sample0 = adapter.get_sample(0)
    assert "sample_id" in sample0
    assert "image" in sample0
    assert len(sample0["annotations"]) == 1


def test_coco_missing_image_file(temp_dir: Path, make_png):
    """Test validation fails with explicit error when an image file is missing."""
    ds_dir = temp_dir / "missing_img_coco"
    ds_dir.mkdir()
    images_dir = ds_dir / "images"
    images_dir.mkdir()

    # Only create img1, not img2
    (images_dir / "img1.png").write_bytes(make_png(width=100, height=100))

    coco_data = {
        "categories": [{"id": 1, "name": "target"}],
        "images": [
            {"id": 1, "file_name": "images/img1.png", "width": 100, "height": 100},
            {"id": 2, "file_name": "images/missing_img.png", "width": 100, "height": 100},
        ],
        "annotations": [
            {"id": 1, "image_id": 1, "category_id": 1, "bbox": [10, 10, 20, 20]},
            {"id": 2, "image_id": 2, "category_id": 1, "bbox": [10, 10, 20, 20]},
        ],
    }
    ann_file = ds_dir / "annotations.json"
    ann_file.write_text(json.dumps(coco_data), encoding="utf-8")

    adapter = COCOAdapter(ds_dir, annotation_file=ann_file)
    val = adapter.validate()
    assert val.is_valid is False
    assert any("not found on disk" in err for err in val.errors)

    with pytest.raises(CVIFFormatError, match="Cannot load invalid COCO dataset"):
        adapter.load()


def test_coco_orphan_annotation_and_unknown_category(temp_dir: Path, make_png):
    """Test validation detects orphan annotations and unknown category references."""
    ds_dir = temp_dir / "orphan_coco"
    ds_dir.mkdir()
    (ds_dir / "img1.png").write_bytes(make_png())

    coco_data = {
        "categories": [{"id": 1, "name": "vehicle"}],
        "images": [{"id": 1, "file_name": "img1.png", "width": 100, "height": 80}],
        "annotations": [
            # Orphan annotation (image_id 999 does not exist)
            {"id": 10, "image_id": 999, "category_id": 1, "bbox": [5, 5, 20, 20]},
            # Unknown category annotation (category_id 888 does not exist)
            {"id": 11, "image_id": 1, "category_id": 888, "bbox": [5, 5, 20, 20]},
        ],
    }
    ann_file = ds_dir / "annotations.json"
    ann_file.write_text(json.dumps(coco_data), encoding="utf-8")

    adapter = COCOAdapter(ds_dir, annotation_file=ann_file)
    val = adapter.validate()
    assert val.is_valid is False
    assert any("Orphan annotation" in err for err in val.errors)
    assert any("references unknown category_id '888'" in err for err in val.errors)


def test_coco_invalid_bounding_boxes(temp_dir: Path, make_png):
    """Test validation catches malformed or non-positive bounding box dimensions."""
    ds_dir = temp_dir / "bad_bbox_coco"
    ds_dir.mkdir()
    (ds_dir / "img.png").write_bytes(make_png())

    coco_data = {
        "categories": [{"id": 1, "name": "target"}],
        "images": [{"id": 1, "file_name": "img.png", "width": 100, "height": 80}],
        "annotations": [
            # Non-positive width
            {"id": 1, "image_id": 1, "category_id": 1, "bbox": [10, 10, 0, 20]},
            # Malformed bbox (3 values instead of 4)
            {"id": 2, "image_id": 1, "category_id": 1, "bbox": [10, 10, 20]},
        ],
    }
    ann_file = ds_dir / "annotations.json"
    ann_file.write_text(json.dumps(coco_data), encoding="utf-8")

    adapter = COCOAdapter(ds_dir, annotation_file=ann_file)
    val = adapter.validate()
    assert val.is_valid is False
    assert any("non-positive width or height" in err for err in val.errors)
    assert any("expected 4 numbers" in err for err in val.errors)


def test_coco_path_traversal_sanitization(temp_dir: Path, make_png):
    """Test that path traversal attempts in file_name are rejected without crashing."""
    ds_dir = temp_dir / "traversal_coco"
    ds_dir.mkdir()
    (ds_dir / "legit.png").write_bytes(make_png())

    coco_data = {
        "categories": [{"id": 1, "name": "target"}],
        "images": [
            {"id": 1, "file_name": "../../etc/shadow", "width": 100, "height": 80},
            {"id": 2, "file_name": "..\\..\\windows\\system32\\calc.exe", "width": 100, "height": 80},
        ],
        "annotations": [],
    }
    ann_file = ds_dir / "annotations.json"
    ann_file.write_text(json.dumps(coco_data), encoding="utf-8")

    adapter = COCOAdapter(ds_dir, annotation_file=ann_file)
    val = adapter.validate()
    assert val.is_valid is False
    assert any("not found on disk" in err for err in val.errors)


def test_coco_malformed_json(temp_dir: Path):
    """Test validation reports error on malformed or corrupted JSON file."""
    ds_dir = temp_dir / "corrupted_json_coco"
    ds_dir.mkdir()
    ann_file = ds_dir / "annotations.json"
    ann_file.write_text("{ unclosed json: ...", encoding="utf-8")

    adapter = COCOAdapter(ds_dir, annotation_file=ann_file)
    val = adapter.validate()
    assert val.is_valid is False
    assert any("Malformed JSON" in err for err in val.errors)


REAL_COCO_DATASET_PATH = Path(
    r"C:\Users\Namith Singh\OneDrive\Documents\datasets for sih\coco\COCO Subset.v4-80-15-5-ratio-with-5-classes.coco"
)


def test_coco_format_detector_split_first(temp_dir: Path):
    """Test FormatDetector detects split-first COCO layouts and rejects arbitrary JSON."""
    # 1. train/_annotations.coco.json
    ds_train = temp_dir / "ds_train"
    (ds_train / "train").mkdir(parents=True)
    coco_meta = {
        "images": [{"id": 1, "file_name": "a.jpg"}],
        "annotations": [],
        "categories": [{"id": 1, "name": "c"}],
    }
    (ds_train / "train" / "_annotations.coco.json").write_text(json.dumps(coco_meta), encoding="utf-8")
    assert FormatDetector.detect(ds_train) == ("coco", "coco_split_first")

    # 2. valid/annotations.json
    ds_valid = temp_dir / "ds_valid"
    (ds_valid / "valid").mkdir(parents=True)
    (ds_valid / "valid" / "annotations.json").write_text(json.dumps(coco_meta), encoding="utf-8")
    assert FormatDetector.detect(ds_valid) == ("coco", "coco_split_first")

    # 3. val/instances.json
    ds_val = temp_dir / "ds_val"
    (ds_val / "val").mkdir(parents=True)
    (ds_val / "val" / "instances.json").write_text(json.dumps(coco_meta), encoding="utf-8")
    assert FormatDetector.detect(ds_val) == ("coco", "coco_split_first")

    # 4. test/instances_test.json
    ds_test = temp_dir / "ds_test"
    (ds_test / "test").mkdir(parents=True)
    (ds_test / "test" / "instances_test.json").write_text(json.dumps(coco_meta), encoding="utf-8")
    assert FormatDetector.detect(ds_test) == ("coco", "coco_split_first")

    # 5. Non-COCO arbitrary JSON in split directory must NOT detect as COCO
    ds_non_coco = temp_dir / "ds_non_coco"
    (ds_non_coco / "train").mkdir(parents=True)
    (ds_non_coco / "train" / "random.json").write_text(json.dumps({"some_key": "some_value"}), encoding="utf-8")
    fmt, _ = FormatDetector.detect(ds_non_coco)
    assert fmt != "coco"


@pytest.mark.parametrize("split_name", ["train", "valid", "val", "test"])
def test_coco_split_first_individual_splits(temp_dir: Path, make_png, split_name: str):
    """Test individual split-first directories (train, valid, val, test) resolve images and populate splits."""
    ds_dir = temp_dir / f"split_{split_name}"
    split_dir = ds_dir / split_name
    split_dir.mkdir(parents=True)

    img_bytes = make_png(width=100, height=100)
    (split_dir / "sample.png").write_bytes(img_bytes)

    coco_data = {
        "categories": [{"id": 1, "name": "widget"}],
        "images": [{"id": 0, "file_name": "sample.png", "width": 100, "height": 100}],
        "annotations": [{"id": 0, "image_id": 0, "category_id": 1, "bbox": [10, 10, 20, 20]}],
    }
    (split_dir / "_annotations.coco.json").write_text(json.dumps(coco_data), encoding="utf-8")

    adapter = COCOAdapter(ds_dir)
    val = adapter.validate()
    assert val.is_valid is True
    assert val.total_samples == 1
    assert val.stats["missing_images"] == 0

    unified = adapter.load()
    assert len(unified.images) == 1
    assert unified.images[0].image_id == f"{split_name}_0"
    assert unified.annotations[0].image_id == f"{split_name}_0"
    assert unified.splits is not None
    assert split_name in unified.splits
    assert unified.splits[split_name] == [f"{split_name}_0"]


def test_coco_multi_split_id_collision_namespacing(temp_dir: Path, make_png):
    """Test multiple split manifests with repeating raw IDs are deterministically namespaced."""
    ds_dir = temp_dir / "multi_split_collision"
    splits = ["train", "valid", "test"]

    for s in splits:
        s_dir = ds_dir / s
        s_dir.mkdir(parents=True)
        (s_dir / f"{s}_img.png").write_bytes(make_png(width=100, height=100))

        # Every split reuses raw image id 0 and raw annotation id 0
        coco_data = {
            "categories": [{"id": 1, "name": "vehicle"}, {"id": 2, "name": "pedestrian"}],
            "images": [{"id": 0, "file_name": f"{s}_img.png", "width": 100, "height": 100}],
            "annotations": [
                {"id": 0, "image_id": 0, "category_id": 1, "bbox": [10, 10, 30, 30], "area": 900.0}
            ],
        }
        (s_dir / "_annotations.coco.json").write_text(json.dumps(coco_data), encoding="utf-8")

    adapter = COCOAdapter(ds_dir)
    assert len(adapter.split_manifests) == 3

    val = adapter.validate()
    assert val.is_valid is True
    assert val.total_samples == 3
    assert val.stats["total_images"] == 3
    assert val.stats["total_annotations"] == 3
    assert val.stats["orphan_annotations"] == 0
    assert len(val.errors) == 0

    unified = adapter.load()
    assert len(unified.images) == 3
    assert len(unified.annotations) == 3
    assert len(unified.classes) == 2

    # Check namespacing of images and annotations
    img_ids = {img.image_id for img in unified.images}
    assert img_ids == {"train_0", "valid_0", "test_0"}

    ann_img_refs = {ann.image_id for ann in unified.annotations}
    assert ann_img_refs == {"train_0", "valid_0", "test_0"}

    ann_ids = {ann.annotation_id for ann in unified.annotations}
    assert ann_ids == {"train_0", "valid_0", "test_0"}

    # Check splits dictionary
    assert unified.splits == {
        "train": ["train_0"],
        "valid": ["valid_0"],
        "test": ["test_0"],
    }

    # Verify deterministic hash
    h1 = unified.compute_dataset_hash()
    h2 = unified.compute_dataset_hash()
    assert h1 == h2 and len(h1) == 64

    # Verify sample fetch
    sample_train = adapter.get_sample(0)
    assert sample_train["sample_id"] == unified.images[0].image_id
    assert len(sample_train["annotations"]) == 1
    assert sample_train["annotations"][0].image_id == unified.images[0].image_id


def test_coco_annotations_dir_multi_split(temp_dir: Path, make_png):
    """Test discovery and aggregation of multi-split manifests in annotations/ directory."""
    ds_dir = temp_dir / "ann_dir_coco"
    ann_dir = ds_dir / "annotations"
    ann_dir.mkdir(parents=True)
    images_dir = ds_dir / "images"
    images_dir.mkdir(parents=True)

    (images_dir / "tr.png").write_bytes(make_png())
    (images_dir / "va.png").write_bytes(make_png())

    train_data = {
        "categories": [{"id": 1, "name": "car"}],
        "images": [{"id": 1, "file_name": "tr.png", "width": 100, "height": 80}],
        "annotations": [{"id": 1, "image_id": 1, "category_id": 1, "bbox": [5, 5, 20, 20]}],
    }
    val_data = {
        "categories": [{"id": 1, "name": "car"}],
        "images": [{"id": 1, "file_name": "va.png", "width": 100, "height": 80}],
        "annotations": [{"id": 1, "image_id": 1, "category_id": 1, "bbox": [10, 10, 15, 15]}],
    }
    (ann_dir / "instances_train.json").write_text(json.dumps(train_data), encoding="utf-8")
    (ann_dir / "instances_val.json").write_text(json.dumps(val_data), encoding="utf-8")

    adapter = COCOAdapter(ds_dir)
    assert len(adapter.split_manifests) == 2

    val = adapter.validate()
    assert val.is_valid is True
    assert val.total_samples == 2

    unified = adapter.load()
    assert len(unified.images) == 2
    assert "train" in unified.splits
    assert "val" in unified.splits


def test_coco_zero_match_validation_failure(temp_dir: Path):
    """Test validation fails clearly when annotation file exists but 0 images resolve or exist."""
    # Subcase A: images declared in manifest but none exist on disk
    ds_dir = temp_dir / "zero_match_coco"
    train_dir = ds_dir / "train"
    train_dir.mkdir(parents=True)

    coco_data = {
        "categories": [{"id": 1, "name": "ghost"}],
        "images": [{"id": 1, "file_name": "does_not_exist.jpg", "width": 100, "height": 100}],
        "annotations": [{"id": 1, "image_id": 1, "category_id": 1, "bbox": [1, 1, 10, 10]}],
    }
    (train_dir / "_annotations.coco.json").write_text(json.dumps(coco_data), encoding="utf-8")

    adapter = COCOAdapter(ds_dir)
    val = adapter.validate()
    assert val.is_valid is False
    assert any("not found on disk" in err for err in val.errors)
    with pytest.raises(CVIFFormatError):
        adapter.load()

    # Subcase B: manifest contains completely empty lists
    ds_empty = temp_dir / "empty_manifest_coco"
    train_empty = ds_empty / "train"
    train_empty.mkdir(parents=True)
    (train_empty / "_annotations.coco.json").write_text(
        json.dumps({"categories": [], "images": [], "annotations": []}), encoding="utf-8"
    )
    adapter_empty = COCOAdapter(ds_empty)
    val_empty = adapter_empty.validate()
    assert val_empty.is_valid is False
    assert any("contain zero images and zero annotations" in err for err in val_empty.errors)


def test_coco_split_first_missing_and_orphan_detection(temp_dir: Path, make_png):
    """Test split-first missing image and orphan annotation reporting."""
    ds_dir = temp_dir / "split_errors_coco"
    train_dir = ds_dir / "train"
    train_dir.mkdir(parents=True)
    (train_dir / "valid_image.png").write_bytes(make_png())

    coco_data = {
        "categories": [{"id": 1, "name": "item"}],
        "images": [
            {"id": 0, "file_name": "valid_image.png", "width": 100, "height": 100},
            {"id": 1, "file_name": "missing.png", "width": 100, "height": 100},
        ],
        "annotations": [
            {"id": 0, "image_id": 0, "category_id": 1, "bbox": [5, 5, 20, 20]},
            {"id": 1, "image_id": 999, "category_id": 1, "bbox": [10, 10, 20, 20]},
        ],
    }
    (train_dir / "_annotations.coco.json").write_text(json.dumps(coco_data), encoding="utf-8")

    adapter = COCOAdapter(ds_dir)
    val = adapter.validate()
    assert val.is_valid is False
    assert any("not found on disk" in err for err in val.errors)
    assert any("Orphan annotation" in err for err in val.errors)
    assert val.stats["missing_images"] == 1
    assert val.stats["orphan_annotations"] == 1


@pytest.mark.skipif(not REAL_COCO_DATASET_PATH.exists(), reason="Real verification dataset not present")
def test_coco_real_dataset_verification():
    """Verify the real split-first COCO dataset from SIH benchmark satisfies all requirements."""
    # 1. Format Detection
    fmt, variant = FormatDetector.detect(REAL_COCO_DATASET_PATH)
    assert fmt == "coco"
    assert variant == "coco_split_first"

    # 2. Manifest Discovery
    adapter = COCOAdapter(REAL_COCO_DATASET_PATH)
    splits_discovered = {split for split, _ in adapter.split_manifests}
    assert splits_discovered == {"train", "valid", "test"}

    # 3. Validation
    val = adapter.validate()
    assert val.is_valid is True
    assert val.total_samples == 100
    assert len(val.errors) == 0
    assert val.stats["verified_images"] == 100
    assert val.stats["missing_images"] == 0
    assert val.stats["total_annotations"] == 392
    assert val.stats["total_categories"] == 6
    assert val.stats["orphan_annotations"] == 0
    assert val.stats["invalid_bboxes"] == 0

    # 4. Load & Aggregation
    unified = adapter.load(compute_hashes=True)
    assert len(unified.images) == 100
    assert len(unified.annotations) == 392
    assert len(unified.classes) == 6
    assert unified.splits is not None
    assert len(unified.splits["train"]) == 80
    assert len(unified.splits["valid"]) == 15
    assert len(unified.splits["test"]) == 5

    # 5. Deterministic Namespacing
    assert all(img.image_id.startswith(("train_", "valid_", "test_")) for img in unified.images)
    assert all(ann.image_id.startswith(("train_", "valid_", "test_")) for ann in unified.annotations)
    assert len(unified.dataset_hash) == 64

    # 6. DT-1 through DT-6 Threat Scan Execution
    orchestrator = DatasetIntegrityOrchestrator()
    session = orchestrator.run_analysis(unified)
    assert session.status == "COMPLETED"
    assert len(session.executed_analyses) > 0

