"""Unit tests for deterministic dataset and sample cryptographic identity hashing."""

import json
from pathlib import Path
import pytest

from cvif.core.schemas import AnnotationRecord, ClassInfo, ImageRecord, UnifiedDataset
from cvif.ingestion.adapters.coco import COCOAdapter


def test_dataset_identity_determinism(temp_dir: Path, make_png):
    """Verify that identical dataset content produces the exact same dataset_hash across runs."""
    ds_dir = temp_dir / "ds_det"
    ds_dir.mkdir()
    (ds_dir / "images").mkdir()
    (ds_dir / "images" / "a.png").write_bytes(make_png(width=100, height=100, fill_byte=10))
    (ds_dir / "images" / "b.png").write_bytes(make_png(width=100, height=100, fill_byte=20))

    coco = {
        "categories": [{"id": 1, "name": "truck"}],
        "images": [
            {"id": 1, "file_name": "images/a.png", "width": 100, "height": 100},
            {"id": 2, "file_name": "images/b.png", "width": 100, "height": 100},
        ],
        "annotations": [
            {"id": 10, "image_id": 1, "category_id": 1, "bbox": [10, 10, 50, 50]},
            {"id": 11, "image_id": 2, "category_id": 1, "bbox": [20, 20, 30, 30]},
        ],
    }
    (ds_dir / "annotations.json").write_text(json.dumps(coco), encoding="utf-8")

    adapter1 = COCOAdapter(ds_dir, annotation_file=ds_dir / "annotations.json")
    ds1 = adapter1.load()

    adapter2 = COCOAdapter(ds_dir, annotation_file=ds_dir / "annotations.json")
    ds2 = adapter2.load()

    assert ds1.dataset_hash == ds2.dataset_hash
    assert len(ds1.dataset_hash) == 64


def test_dataset_identity_changes_on_image_modification(temp_dir: Path, make_png):
    """Verify modifying image content alters the dataset_hash."""
    ds_dir = temp_dir / "ds_mod_img"
    ds_dir.mkdir()
    (ds_dir / "images").mkdir()
    img_file = ds_dir / "images" / "sample.png"
    img_file.write_bytes(make_png(width=100, height=100, fill_byte=10))

    coco = {
        "categories": [{"id": 1, "name": "truck"}],
        "images": [{"id": 1, "file_name": "images/sample.png", "width": 100, "height": 100}],
        "annotations": [{"id": 10, "image_id": 1, "category_id": 1, "bbox": [10, 10, 50, 50]}],
    }
    (ds_dir / "annotations.json").write_text(json.dumps(coco), encoding="utf-8")

    adapter = COCOAdapter(ds_dir, annotation_file=ds_dir / "annotations.json")
    ds_before = adapter.load()
    hash_before = ds_before.dataset_hash

    # Modify image file byte content
    img_file.write_bytes(make_png(width=100, height=100, fill_byte=99))

    adapter_after = COCOAdapter(ds_dir, annotation_file=ds_dir / "annotations.json")
    ds_after = adapter_after.load()
    hash_after = ds_after.dataset_hash

    assert hash_before != hash_after


def test_dataset_identity_changes_on_annotation_modification(temp_dir: Path, make_png):
    """Verify modifying an annotation coordinate or category alters the dataset_hash."""
    ds_dir = temp_dir / "ds_mod_ann"
    ds_dir.mkdir()
    (ds_dir / "images").mkdir()
    (ds_dir / "images" / "sample.png").write_bytes(make_png(width=100, height=100))

    coco = {
        "categories": [{"id": 1, "name": "truck"}, {"id": 2, "name": "car"}],
        "images": [{"id": 1, "file_name": "images/sample.png", "width": 100, "height": 100}],
        "annotations": [{"id": 10, "image_id": 1, "category_id": 1, "bbox": [10, 10, 50, 50]}],
    }
    ann_file = ds_dir / "annotations.json"
    ann_file.write_text(json.dumps(coco), encoding="utf-8")

    adapter1 = COCOAdapter(ds_dir, annotation_file=ann_file)
    ds1 = adapter1.load()

    # Change bbox coordinate slightly
    coco["annotations"][0]["bbox"] = [10, 10, 51, 50]
    ann_file.write_text(json.dumps(coco), encoding="utf-8")

    adapter2 = COCOAdapter(ds_dir, annotation_file=ann_file)
    ds2 = adapter2.load()

    assert ds1.dataset_hash != ds2.dataset_hash


def test_dataset_identity_changes_on_contributor_change(temp_dir: Path, make_png):
    """Verify modifying contributor provenance alters the dataset_hash."""
    ds_dir = temp_dir / "ds_contrib"
    ds_dir.mkdir()
    (ds_dir / "images").mkdir()
    (ds_dir / "images" / "sample.png").write_bytes(make_png(width=100, height=100))

    coco = {
        "info": {"contributor": "Analyst_A"},
        "categories": [{"id": 1, "name": "truck"}],
        "images": [{"id": 1, "file_name": "images/sample.png", "width": 100, "height": 100}],
        "annotations": [{"id": 10, "image_id": 1, "category_id": 1, "bbox": [10, 10, 50, 50]}],
    }
    ann_file = ds_dir / "annotations.json"
    ann_file.write_text(json.dumps(coco), encoding="utf-8")

    ds1 = COCOAdapter(ds_dir, annotation_file=ann_file).load()

    coco["info"]["contributor"] = "Analyst_B"
    ann_file.write_text(json.dumps(coco), encoding="utf-8")

    ds2 = COCOAdapter(ds_dir, annotation_file=ann_file).load()

    assert ds1.dataset_hash != ds2.dataset_hash


def test_dataset_identity_ordering_invariance():
    """Verify that reordering the images or annotations list in memory does NOT alter the hash."""
    img_a = ImageRecord(image_id="1", file_path="images/a.png", file_hash="hash_a", width=100, height=100)
    img_b = ImageRecord(image_id="2", file_path="images/b.png", file_hash="hash_b", width=100, height=100)

    ann_1 = AnnotationRecord(annotation_id="a1", image_id="1", class_id=0, class_name="c0", bbox=[0.1, 0.1, 0.5, 0.5])
    ann_2 = AnnotationRecord(annotation_id="a2", image_id="2", class_id=1, class_name="c1", bbox=[0.2, 0.2, 0.6, 0.6])

    cls_0 = ClassInfo(class_id=0, class_name="c0", count=1)
    cls_1 = ClassInfo(class_id=1, class_name="c1", count=1)

    ds_order1 = UnifiedDataset(
        dataset_root="/data",
        format_origin="yolo",
        images=[img_a, img_b],
        annotations=[ann_1, ann_2],
        classes=[cls_0, cls_1],
    )
    hash1 = ds_order1.compute_dataset_hash()

    # Inverted order
    ds_order2 = UnifiedDataset(
        dataset_root="/data",
        format_origin="yolo",
        images=[img_b, img_a],
        annotations=[ann_2, ann_1],
        classes=[cls_1, cls_0],
    )
    hash2 = ds_order2.compute_dataset_hash()

    assert hash1 == hash2
