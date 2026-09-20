"""Unit tests for YOLO dataset ingestion adapter across split, flat, and paired layouts."""

from pathlib import Path
import pytest
import yaml

from cvif.core.exceptions import CVIFFormatError
from cvif.core.schemas import UnifiedDataset, ValidationResult
from cvif.ingestion.adapters.yolo import YOLOAdapter


def test_yolo_standard_split_layout(temp_dir: Path, make_jpeg):
    """Test standard YOLO layout with images/{train,val} and labels/{train,val} and data.yaml."""
    ds_dir = temp_dir / "yolo_split"
    ds_dir.mkdir()

    # Create directories
    (ds_dir / "images" / "train").mkdir(parents=True)
    (ds_dir / "images" / "val").mkdir(parents=True)
    (ds_dir / "labels" / "train").mkdir(parents=True)
    (ds_dir / "labels" / "val").mkdir(parents=True)

    # Write images
    (ds_dir / "images" / "train" / "img1.jpg").write_bytes(make_jpeg(width=640, height=480))
    (ds_dir / "images" / "val" / "img2.jpg").write_bytes(make_jpeg(width=640, height=480))

    # Write label files: class_id center_x center_y width height
    (ds_dir / "labels" / "train" / "img1.txt").write_text("0 0.5 0.5 0.4 0.4\n1 0.2 0.2 0.1 0.1\n")
    (ds_dir / "labels" / "val" / "img2.txt").write_text("0 0.8 0.8 0.2 0.2\n")

    # Write data.yaml
    data_yaml = {
        "train": "images/train",
        "val": "images/val",
        "names": ["armored_vehicle", "command_post"],
        "contributor": "Sensors_Division_1",
    }
    (ds_dir / "data.yaml").write_text(yaml.dump(data_yaml))

    adapter = YOLOAdapter(ds_dir)
    assert adapter.format_name == "yolo"

    val = adapter.validate()
    assert val.is_valid is True
    assert val.total_samples == 2
    assert val.stats["total_annotations"] == 3
    assert val.stats["declared_classes"] == 2

    unified = adapter.load()
    assert isinstance(unified, UnifiedDataset)
    assert unified.format_origin == "yolo"
    assert len(unified.images) == 2
    assert len(unified.annotations) == 3
    assert unified.contributor_id == "Sensors_Division_1"
    assert unified.splits is not None
    assert "train" in unified.splits
    assert "val" in unified.splits
    assert len(unified.dataset_hash) == 64

    # Check normalized bounding box calculation from (xc, yc, w, h)
    # For img1: xc=0.5, yc=0.5, bw=0.4, bh=0.4 -> x_min=0.3, y_min=0.3, x_max=0.7, y_max=0.7
    ann0 = unified.annotations[0]
    assert ann0.class_name == "armored_vehicle"
    assert ann0.bbox is not None
    assert pytest.approx(ann0.bbox[0], 0.01) == 0.3
    assert pytest.approx(ann0.bbox[1], 0.01) == 0.3
    assert pytest.approx(ann0.bbox[2], 0.01) == 0.7
    assert pytest.approx(ann0.bbox[3], 0.01) == 0.7


def test_yolo_flat_layout(temp_dir: Path, make_jpeg):
    """Test flat YOLO layout with images/ and labels/ at root."""
    ds_dir = temp_dir / "yolo_flat"
    ds_dir.mkdir()
    (ds_dir / "images").mkdir()
    (ds_dir / "labels").mkdir()

    (ds_dir / "images" / "flat1.jpg").write_bytes(make_jpeg(width=640, height=640))
    (ds_dir / "labels" / "flat1.txt").write_text("0 0.5 0.5 0.5 0.5\n")

    adapter = YOLOAdapter(ds_dir)
    val = adapter.validate()
    assert val.is_valid is True
    assert val.total_samples == 1

    unified = adapter.load()
    assert len(unified.images) == 1
    assert len(unified.annotations) == 1


def test_yolo_paired_layout_without_data_yaml(temp_dir: Path, make_jpeg):
    """Test paired layout (image and .txt together) without data.yaml, verifying synthetic class fallback."""
    ds_dir = temp_dir / "yolo_paired"
    ds_dir.mkdir()

    (ds_dir / "sample_a.jpg").write_bytes(make_jpeg())
    (ds_dir / "sample_a.txt").write_text("0 0.4 0.4 0.2 0.2\n2 0.6 0.6 0.2 0.2\n")

    adapter = YOLOAdapter(ds_dir)
    val = adapter.validate()
    assert val.is_valid is True

    unified = adapter.load()
    assert len(unified.images) == 1
    assert len(unified.annotations) == 2
    # Verify fallback to synthetic class names
    class_names = [c.class_name for c in unified.classes]
    assert "class_0" in class_names
    assert "class_2" in class_names
    assert unified.contributor_id is None  # Never invent contributor provenance


def test_yolo_polygon_segmentation_support(temp_dir: Path, make_jpeg):
    """Test YOLOv8 polygon segmentation annotations are converted to enclosing bounding box envelope."""
    ds_dir = temp_dir / "yolo_segmentation"
    ds_dir.mkdir()

    (ds_dir / "poly.jpg").write_bytes(make_jpeg(width=500, height=500))
    # Polygon with 4 vertices (8 coordinates): (0.1, 0.2), (0.5, 0.2), (0.5, 0.8), (0.1, 0.8)
    poly_line = "0 0.1 0.2 0.5 0.2 0.5 0.8 0.1 0.8\n"
    (ds_dir / "poly.txt").write_text(poly_line)

    adapter = YOLOAdapter(ds_dir)
    val = adapter.validate()
    assert val.is_valid is True

    unified = adapter.load()
    assert len(unified.annotations) == 1
    ann = unified.annotations[0]
    assert ann.bbox is not None
    # Envelope x_min=0.1, y_min=0.2, x_max=0.5, y_max=0.8
    assert pytest.approx(ann.bbox[0], 0.01) == 0.1
    assert pytest.approx(ann.bbox[1], 0.01) == 0.2
    assert pytest.approx(ann.bbox[2], 0.01) == 0.5
    assert pytest.approx(ann.bbox[3], 0.01) == 0.8
    assert ann.segmentation == [0.1, 0.2, 0.5, 0.2, 0.5, 0.8, 0.1, 0.8]


def test_yolo_malformed_annotation_validation(temp_dir: Path, make_jpeg):
    """Test validation catches various malformed YOLO annotation lines."""
    ds_dir = temp_dir / "yolo_malformed"
    ds_dir.mkdir()

    (ds_dir / "bad.jpg").write_bytes(make_jpeg())
    # Malformed lines: insufficient tokens, negative class, non-numeric, non-positive dim
    bad_lines = (
        "0 0.5 0.5 0.2\n"  # Only 4 tokens
        "-1 0.5 0.5 0.2 0.2\n"  # Negative class ID
        "0 not_a_float 0.5 0.2 0.2\n"  # Non-numeric coordinate
        "0 0.5 0.5 -0.1 0.2\n"  # Non-positive width
    )
    (ds_dir / "bad.txt").write_text(bad_lines)

    adapter = YOLOAdapter(ds_dir)
    val = adapter.validate()
    assert val.is_valid is False
    assert len(val.errors) >= 3
    assert any("expected >= 5 tokens" in err for err in val.errors)
    assert any("Negative class ID" in err for err in val.errors)
    assert any("Non-numeric coordinate" in err for err in val.errors)
    assert any("Non-positive width/height" in err for err in val.errors)


def test_yolo_orphan_labels_and_unannotated_images(temp_dir: Path, make_jpeg):
    """Test orphan label files and unannotated images produce non-fatal warnings when partial matches exist."""
    ds_dir = temp_dir / "yolo_orphans"
    ds_dir.mkdir()

    # Paired image and label
    (ds_dir / "valid_pair.jpg").write_bytes(make_jpeg())
    (ds_dir / "valid_pair.txt").write_text("0 0.5 0.5 0.2 0.2\n")

    # Image without label
    (ds_dir / "image_alone.jpg").write_bytes(make_jpeg())
    # Label without image
    (ds_dir / "orphan_label.txt").write_text("0 0.5 0.5 0.2 0.2\n")

    adapter = YOLOAdapter(ds_dir)
    val = adapter.validate()
    # Errors are 0 (non-fatal), but warnings are recorded
    assert val.is_valid is True
    assert any("Orphan label file" in w for w in val.warnings)
    assert any("unannotated" in w.lower() or "missing" in w.lower() for w in val.warnings)


def test_yolo_validation_fails_when_all_labels_unmatched(temp_dir: Path, make_jpeg):
    """Test validation fails with explicit error if label files exist but none match image layout."""
    ds_dir = temp_dir / "yolo_unmatched_labels"
    ds_dir.mkdir()

    # Image without matching label
    (ds_dir / "image_alone.jpg").write_bytes(make_jpeg())
    # Label with non-matching stem
    (ds_dir / "orphan_label.txt").write_text("0 0.5 0.5 0.2 0.2\n")

    adapter = YOLOAdapter(ds_dir)
    val = adapter.validate()
    assert val.is_valid is False
    assert any("none matched image directory layout" in err for err in val.errors)
    assert any("Found 1 label files but none matched image directory layout" in err for err in val.errors)


def test_yolo_image_only_dataset_passes_validation(temp_dir: Path, make_jpeg):
    """Test legitimate image-only dataset (zero label files) validates without error."""
    ds_dir = temp_dir / "yolo_image_only"
    ds_dir.mkdir()

    (ds_dir / "sample1.jpg").write_bytes(make_jpeg())
    (ds_dir / "sample2.jpg").write_bytes(make_jpeg())

    adapter = YOLOAdapter(ds_dir)
    val = adapter.validate()
    assert val.is_valid is True
    assert val.total_samples == 2
    assert val.stats["total_annotations"] == 0
    assert any("2 image(s) have missing or empty label files" in w for w in val.warnings)


def test_yolo_split_first_standard_layout(temp_dir: Path, make_jpeg):
    """Test standard Roboflow/Ultralytics split-first layout: {train,valid,test}/images and labels."""
    ds_dir = temp_dir / "yolo_split_first"
    ds_dir.mkdir()

    # Create split-first hierarchy
    for split in ("train", "valid", "test"):
        (ds_dir / split / "images").mkdir(parents=True)
        (ds_dir / split / "labels").mkdir(parents=True)

    # train: 2 pairs
    (ds_dir / "train" / "images" / "tr1.jpg").write_bytes(make_jpeg(width=640, height=480))
    (ds_dir / "train" / "labels" / "tr1.txt").write_text("0 0.5 0.5 0.4 0.4\n")
    (ds_dir / "train" / "images" / "tr2.jpg").write_bytes(make_jpeg(width=640, height=480))
    (ds_dir / "train" / "labels" / "tr2.txt").write_text("1 0.3 0.3 0.2 0.2\n")

    # valid: 1 pair
    (ds_dir / "valid" / "images" / "va1.jpg").write_bytes(make_jpeg(width=640, height=480))
    (ds_dir / "valid" / "labels" / "va1.txt").write_text("0 0.6 0.6 0.2 0.2\n")

    # test: 1 pair
    (ds_dir / "test" / "images" / "te1.jpg").write_bytes(make_jpeg(width=640, height=480))
    (ds_dir / "test" / "labels" / "te1.txt").write_text("1 0.7 0.7 0.3 0.3\n")

    data_yaml = {
        "train": "train/images",
        "val": "valid/images",
        "test": "test/images",
        "names": ["cat", "dog"],
    }
    (ds_dir / "data.yaml").write_text(yaml.dump(data_yaml))

    adapter = YOLOAdapter(ds_dir)
    val = adapter.validate()
    assert val.is_valid is True
    assert val.total_samples == 4
    assert val.stats["total_annotations"] == 4
    assert val.stats["unannotated_images"] == 0
    assert val.stats["orphan_labels"] == 0

    unified = adapter.load()
    assert len(unified.images) == 4
    assert len(unified.annotations) == 4
    assert unified.splits is not None
    assert set(unified.splits.keys()) == {"train", "valid", "test"}
    assert len(unified.splits["train"]) == 2
    assert len(unified.splits["valid"]) == 1
    assert len(unified.splits["test"]) == 1


def test_yolo_split_first_val_alias_compatibility(temp_dir: Path, make_jpeg):
    """Test split-first layout supporting 'val' as split name."""
    ds_dir = temp_dir / "yolo_val_alias"
    ds_dir.mkdir()

    (ds_dir / "val" / "images").mkdir(parents=True)
    (ds_dir / "val" / "labels").mkdir(parents=True)

    (ds_dir / "val" / "images" / "sample.jpg").write_bytes(make_jpeg())
    (ds_dir / "val" / "labels" / "sample.txt").write_text("0 0.5 0.5 0.5 0.5\n")

    adapter = YOLOAdapter(ds_dir)
    val = adapter.validate()
    assert val.is_valid is True
    assert val.total_samples == 1
    assert val.stats["total_annotations"] == 1

    unified = adapter.load()
    assert "val" in unified.splits
    assert len(unified.splits["val"]) == 1
    assert len(unified.annotations) == 1


def test_yolo_roboflow_style_mini_fixture(temp_dir: Path, make_jpeg):
    """Regression test replicating Roboflow YOLOv8 export with polygon annotations and ../ relative data.yaml paths."""
    ds_dir = temp_dir / "roboflow_mini"
    ds_dir.mkdir()

    for s in ("train", "valid", "test"):
        (ds_dir / s / "images").mkdir(parents=True)
        (ds_dir / s / "labels").mkdir(parents=True)

    # Polygon annotations with >5 tokens
    poly_annot = "0 0.1 0.2 0.5 0.2 0.5 0.8 0.1 0.8\n"
    (ds_dir / "train" / "images" / "dog_tr.jpg").write_bytes(make_jpeg(width=640, height=480))
    (ds_dir / "train" / "labels" / "dog_tr.txt").write_text(poly_annot)

    (ds_dir / "valid" / "images" / "dog_va.jpg").write_bytes(make_jpeg(width=640, height=480))
    (ds_dir / "valid" / "labels" / "dog_va.txt").write_text(poly_annot)

    (ds_dir / "test" / "images" / "dog_te.jpg").write_bytes(make_jpeg(width=640, height=480))
    (ds_dir / "test" / "labels" / "dog_te.txt").write_text(poly_annot)

    # Non-annotation text files that should not be counted as orphans
    (ds_dir / "README.dataset.txt").write_text("Sample dataset README\n")
    (ds_dir / "README.roboflow.txt").write_text("Exported from Roboflow\n")

    # Roboflow data.yaml with ../ relative path prefixes
    data_yaml = {
        "train": "../train/images",
        "val": "../valid/images",
        "test": "../test/images",
        "nc": 1,
        "names": ["dog"],
    }
    (ds_dir / "data.yaml").write_text(yaml.dump(data_yaml))

    adapter = YOLOAdapter(ds_dir)
    val = adapter.validate()
    assert val.is_valid is True
    assert val.total_samples == 3
    assert val.stats["total_annotations"] == 3
    assert val.stats["orphan_labels"] == 0

    unified = adapter.load()
    assert len(unified.images) == 3
    assert len(unified.annotations) == 3
    assert unified.splits == {"train": ["dog_tr"], "valid": ["dog_va"], "test": ["dog_te"]}
    # Verify polygon envelope converted to bounding box
    ann = unified.annotations[0]
    assert ann.class_name == "dog"
    assert ann.bbox is not None
    assert pytest.approx(ann.bbox[0], 0.01) == 0.1
    assert pytest.approx(ann.bbox[1], 0.01) == 0.2
    assert pytest.approx(ann.bbox[2], 0.01) == 0.5
    assert pytest.approx(ann.bbox[3], 0.01) == 0.8


def test_frontend_threat_taxonomy_alignment():
    """Verify frontend DatasetPage.tsx card reflects authoritative DT-1..6 backend threat definitions."""
    frontend_page = Path(__file__).resolve().parents[2] / "frontend" / "src" / "pages" / "DatasetPage.tsx"
    assert frontend_page.is_file(), f"DatasetPage.tsx not found at {frontend_page}"
    content = frontend_page.read_text(encoding="utf-8")

    assert "DT-1 Trigger Injection:" in content
    assert "DT-2 Label Flipping:" in content
    assert "DT-3 Systematic Mislabelling:" in content
    assert "DT-4 Near-Duplicate Flooding:" in content
    assert "DT-5 OOD Insertion:" in content
    assert "DT-6 Contributor Risk:" in content
    assert "Annotation Corruption" not in content

