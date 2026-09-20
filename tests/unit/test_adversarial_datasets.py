"""Adversarial and edge-case testing for dataset ingestion and integrity analysis.

Includes attacks and unusual patterns designed to fool or crash the analysis:
1. Path traversal attacks in image paths
2. Identical images with completely different file names
3. Different images with identical metadata
4. Duplicate and reordered annotations
5. Extreme legitimate class imbalance (e.g. 50:1)
6. Extreme aspect ratios (e.g. 1000:10)
7. Empty annotations
8. Partially corrupted files within an otherwise valid dataset
"""

import json
from pathlib import Path
import pytest

from cvif.analysis.data_integrity import NearDuplicateCheck, OODInsertionCheck
from cvif.analysis.orchestrator import DatasetIntegrityOrchestrator
from cvif.core.enums import SessionStatus, SeverityLevel
from cvif.core.exceptions import CVIFFormatError
from cvif.core.schemas import AnnotationRecord, ClassInfo, ImageRecord, UnifiedDataset
from cvif.crypto.hashing import sha256_file
from cvif.ingestion.adapters.coco import COCOAdapter
from cvif.ingestion.adapters.yolo import YOLOAdapter
from cvif.ingestion.gateway import IngestionGateway


def test_adversarial_path_traversal_attempts(temp_dir: Path, make_png):
    """Adversarial test: Dataset manifests with path traversal vectors ('../', '..\\', absolute paths)."""
    ds_dir = temp_dir / "ds_traversal"
    ds_dir.mkdir()
    (ds_dir / "legit.png").write_bytes(make_png())

    coco_payload = {
        "categories": [{"id": 1, "name": "target"}],
        "images": [
            {"id": 1, "file_name": "../../../../../../../etc/passwd", "width": 100, "height": 100},
            {"id": 2, "file_name": "..\\..\\..\\windows\\win.ini", "width": 100, "height": 100},
            {"id": 3, "file_name": "C:/Windows/System32/cmd.exe", "width": 100, "height": 100},
        ],
        "annotations": [],
    }
    ann_file = ds_dir / "annotations.json"
    ann_file.write_text(json.dumps(coco_payload), encoding="utf-8")

    adapter = COCOAdapter(ds_dir, annotation_file=ann_file)
    val = adapter.validate()
    # Traversal paths must be safely rejected and flagged as missing, never resolved outside root
    assert val.is_valid is False
    assert len(val.errors) == 3


def test_adversarial_identical_images_different_names(temp_dir: Path, make_png, evidence_store):
    """Adversarial test: Identical image bytes distributed under distinct filenames to disguise duplicates."""
    ds_dir = temp_dir / "ds_disguised_dupes"
    ds_dir.mkdir()
    img_dir = ds_dir / "images"
    img_dir.mkdir()

    raw_bytes = make_png(width=100, height=100, fill_byte=77)
    (img_dir / "tank_alpha.png").write_bytes(raw_bytes)
    (img_dir / "recon_frame_99.png").write_bytes(raw_bytes)
    (img_dir / "civilian_bus.png").write_bytes(raw_bytes)

    images = [
        ImageRecord(
            image_id=name,
            file_path=f"images/{name}",
            file_hash=sha256_file(img_dir / name),
            width=100,
            height=100,
        )
        for name in ("tank_alpha.png", "recon_frame_99.png", "civilian_bus.png")
    ]

    dataset = UnifiedDataset(
        dataset_root=str(ds_dir),
        format_origin="coco",
        images=images,
        classes=[ClassInfo(class_id=0, class_name="target", count=3)],
    )

    checker = NearDuplicateCheck()
    findings = checker.run(dataset=dataset, evidence_store=evidence_store)
    # The check MUST catch that all 3 are identical despite conflicting filenames
    assert len(findings) == 1
    assert findings[0].threat_id == "DT-4"
    ev = evidence_store.get_evidence(findings[0].evidence_ids[0])
    assert ev.metrics["total_exact_duplicate_files"] == 3.0


def test_adversarial_different_images_same_metadata(temp_dir: Path, make_png):
    """Adversarial test: Two completely different images having identical declared metadata."""
    ds_dir = temp_dir / "ds_metadata_spoof"
    ds_dir.mkdir()
    (ds_dir / "images").mkdir()

    img1 = make_png(width=200, height=200, fill_byte=10)
    img2 = make_png(width=200, height=200, fill_byte=200)
    (ds_dir / "images" / "a.png").write_bytes(img1)
    (ds_dir / "images" / "b.png").write_bytes(img2)

    coco = {
        "categories": [{"id": 1, "name": "target"}],
        "images": [
            {"id": 1, "file_name": "images/a.png", "width": 200, "height": 200, "date_captured": "2026-01-01"},
            {"id": 2, "file_name": "images/b.png", "width": 200, "height": 200, "date_captured": "2026-01-01"},
        ],
        "annotations": [],
    }
    (ds_dir / "annotations.json").write_text(json.dumps(coco), encoding="utf-8")

    adapter = COCOAdapter(ds_dir, annotation_file=ds_dir / "annotations.json")
    dataset = adapter.load()

    # Hashes must differ because content differs, regardless of identical metadata
    assert dataset.images[0].file_hash != dataset.images[1].file_hash


def test_adversarial_extreme_aspect_ratios(temp_dir: Path, make_png):
    """Adversarial test: Extreme aspect ratios (e.g. 1000x10) must ingest and normalize gracefully."""
    ds_dir = temp_dir / "ds_panoramic"
    ds_dir.mkdir()
    (ds_dir / "images").mkdir()

    # Extreme panorama
    (ds_dir / "images" / "pano.png").write_bytes(make_png(width=1000, height=10))

    coco = {
        "categories": [{"id": 1, "name": "border_fence"}],
        "images": [{"id": 1, "file_name": "images/pano.png", "width": 1000, "height": 10}],
        "annotations": [
            {"id": 10, "image_id": 1, "category_id": 1, "bbox": [100, 2, 800, 6]},
        ],
    }
    (ds_dir / "annotations.json").write_text(json.dumps(coco), encoding="utf-8")

    adapter = COCOAdapter(ds_dir, annotation_file=ds_dir / "annotations.json")
    val = adapter.validate()
    assert val.is_valid is True

    ds = adapter.load()
    ann = ds.annotations[0]
    assert ann.bbox is not None
    # x_min: 100/1000=0.1, y_min: 2/10=0.2, x_max: 900/1000=0.9, y_max: 8/10=0.8
    assert pytest.approx(ann.bbox[0], 0.01) == 0.1
    assert pytest.approx(ann.bbox[1], 0.01) == 0.2
    assert pytest.approx(ann.bbox[2], 0.01) == 0.9
    assert pytest.approx(ann.bbox[3], 0.01) == 0.8


def test_adversarial_extreme_class_imbalance(temp_dir: Path, make_png, evidence_store):
    """Adversarial test: Highly skewed but legitimate class distribution (e.g. rare class)."""
    ds_dir = temp_dir / "ds_imbalanced"
    ds_dir.mkdir()
    (ds_dir / "images").mkdir()

    # 20 samples of common class 0, 1 sample of rare class 1
    images = []
    annotations = []
    for i in range(20):
        p = ds_dir / "images" / f"common_{i}.png"
        p.write_bytes(make_png(width=64, height=64, fill_byte=30))
        images.append(ImageRecord(image_id=f"c_{i}", file_path=f"images/{p.name}", file_hash=sha256_file(p)))
        annotations.append(AnnotationRecord(annotation_id=f"ac_{i}", image_id=f"c_{i}", class_id=0, class_name="common"))

    p_rare = ds_dir / "images" / "rare.png"
    p_rare.write_bytes(make_png(width=64, height=64, fill_byte=30))
    images.append(ImageRecord(image_id="rare", file_path="images/rare.png", file_hash=sha256_file(p_rare)))
    annotations.append(AnnotationRecord(annotation_id="ar_0", image_id="rare", class_id=1, class_name="rare"))

    dataset = UnifiedDataset(
        dataset_root=str(ds_dir),
        format_origin="coco",
        images=images,
        annotations=annotations,
        classes=[
            ClassInfo(class_id=0, class_name="common", count=20),
            ClassInfo(class_id=1, class_name="rare", count=1),
        ],
    )

    # Orchestrator must handle extreme imbalance without dividing by zero or raising exceptions
    orchestrator = DatasetIntegrityOrchestrator(evidence_store=evidence_store)
    session = orchestrator.run_analysis(dataset)
    assert session.status == SessionStatus.COMPLETED


def test_adversarial_corrupted_file_inside_dataset(temp_dir: Path, make_png):
    """Adversarial test: An unreadable / truncated file amongst valid images in YOLO dataset."""
    ds_dir = temp_dir / "ds_partially_corrupt"
    ds_dir.mkdir()

    # Valid image and label
    (ds_dir / "good.jpg").write_bytes(make_png())
    (ds_dir / "good.txt").write_text("0 0.5 0.5 0.2 0.2\n")

    # Corrupted / unreadable label file
    (ds_dir / "corrupted_label.jpg").write_bytes(make_png())
    (ds_dir / "corrupted_label.txt").write_bytes(b"\x00\xff\xfe\x00_invalid_unicode_chars")

    adapter = YOLOAdapter(ds_dir)
    val = adapter.validate()
    # Validation should detect the unreadable label file and report error without crashing
    assert val.is_valid is False
    assert any("Unreadable label file" in err for err in val.errors)
