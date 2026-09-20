"""Unit tests for individual dataset integrity analysis checks (DT-1 through DT-6)."""

from pathlib import Path
import pytest
from uuid import uuid4

from cvif.analysis.data_integrity import (
    ContributorRiskCheck,
    LabelFlippingCheck,
    NearDuplicateCheck,
    OODInsertionCheck,
    SystematicMislabellingCheck,
    TriggerInjectionCheck,
)
from cvif.core.enums import SeverityLevel
from cvif.core.schemas import (
    AnnotationRecord,
    ClassInfo,
    Finding,
    ImageRecord,
    UnifiedDataset,
)
from cvif.crypto.hashing import sha256_file
from cvif.features.statistical import StatisticalFeatureExtractor


def test_near_duplicate_check_exact_and_distinct(temp_dir: Path, make_png, evidence_store):
    """Test DT-4 detection of exact duplicate files (SHA-256 collisions) vs distinct images."""
    ds_dir = temp_dir / "ds_dupes"
    ds_dir.mkdir()
    img_dir = ds_dir / "images"
    img_dir.mkdir()

    # Image 1 and 2 are EXACT duplicates
    img1_bytes = make_png(width=100, height=80, fill_byte=10)
    (img_dir / "img1.png").write_bytes(img1_bytes)
    (img_dir / "img2.png").write_bytes(img1_bytes)

    # Image 3 is completely distinct
    img3_bytes = make_png(width=100, height=80, fill_byte=200)
    (img_dir / "img3.png").write_bytes(img3_bytes)

    images = [
        ImageRecord(
            image_id=f"img_{i}",
            file_path=f"images/img{i}.png",
            file_hash=sha256_file(img_dir / f"img{i}.png"),
            width=100,
            height=80,
            file_size_bytes=len(img1_bytes) if i != 3 else len(img3_bytes),
        )
        for i in (1, 2, 3)
    ]

    dataset = UnifiedDataset(
        dataset_root=str(ds_dir),
        format_origin="coco",
        images=images,
        classes=[ClassInfo(class_id=0, class_name="target", count=3)],
    )

    checker = NearDuplicateCheck()
    assert checker.threat_id == "DT-4"
    assert checker.check_applicable(dataset) is True

    findings = checker.run(dataset=dataset, evidence_store=evidence_store)
    assert len(findings) == 1
    f = findings[0]
    assert f.threat_id == "DT-4"
    assert "Exact Duplicate Images Detected" in f.title
    assert f.severity == SeverityLevel.HIGH
    ev = evidence_store.get_evidence(f.evidence_ids[0])
    assert ev.metrics["total_exact_duplicate_files"] == 2.0


def test_trigger_injection_check_with_synthetic_patch(temp_dir: Path, make_png, evidence_store):
    """Test DT-1 detection of high-frequency corner patch trigger anomalies."""
    ds_dir = temp_dir / "ds_trigger"
    ds_dir.mkdir()
    img_dir = ds_dir / "images"
    img_dir.mkdir()

    # Normal images
    base_bytes = b"X" * 1500
    (img_dir / "norm1.png").write_bytes(base_bytes)
    (img_dir / "norm2.png").write_bytes(base_bytes)

    # Trigger-poisoned image: append high-frequency alternating byte sequence in corner region
    trigger_patch = bytes([0, 255] * 256)
    poisoned_bytes = b"X" * 1500 + trigger_patch
    (img_dir / "poison1.png").write_bytes(poisoned_bytes)

    images = [
        ImageRecord(
            image_id="n1",
            file_path="images/norm1.png",
            file_hash=sha256_file(img_dir / "norm1.png"),
            width=120,
            height=120,
        ),
        ImageRecord(
            image_id="n2",
            file_path="images/norm2.png",
            file_hash=sha256_file(img_dir / "norm2.png"),
            width=120,
            height=120,
        ),
        ImageRecord(
            image_id="p1",
            file_path="images/poison1.png",
            file_hash=sha256_file(img_dir / "poison1.png"),
            width=120,
            height=120,
        ),
    ]

    dataset = UnifiedDataset(
        dataset_root=str(ds_dir),
        format_origin="coco",
        images=images,
        classes=[ClassInfo(class_id=0, class_name="target", count=3)],
    )

    checker = TriggerInjectionCheck()
    assert checker.threat_id == "DT-1"
    assert checker.check_applicable(dataset) is True

    findings = checker.run(dataset=dataset, evidence_store=evidence_store)
    assert len(findings) == 1
    f = findings[0]
    assert f.threat_id == "DT-1"
    assert "Backdoor Trigger" in f.title
    assert "images/poison1.png" in f.affected_assets


def test_label_flipping_check(temp_dir: Path, make_png, evidence_store):
    """Test DT-2 detection when a sample's label contradicts the consensus of its k-NN neighbors."""
    ds_dir = temp_dir / "ds_label_flip"
    ds_dir.mkdir()
    img_dir = ds_dir / "images"
    img_dir.mkdir()

    # Create 5 images with fill_byte=10 (Cluster A), 5 images with fill_byte=200 (Cluster B)
    images = []
    annotations = []

    # Cluster A images: class_id 0
    for i in range(5):
        p = img_dir / f"clA_{i}.png"
        p.write_bytes(make_png(width=64, height=64, fill_byte=10 + i))
        img_id = f"clA_{i}"
        images.append(ImageRecord(image_id=img_id, file_path=f"images/{p.name}", file_hash=sha256_file(p)))
        annotations.append(AnnotationRecord(annotation_id=f"ann_A_{i}", image_id=img_id, class_id=0, class_name="class_0"))

    # Cluster B images: class_id 1
    for i in range(5):
        p = img_dir / f"clB_{i}.png"
        p.write_bytes(make_png(width=64, height=64, fill_byte=200 + i))
        img_id = f"clB_{i}"
        images.append(ImageRecord(image_id=img_id, file_path=f"images/{p.name}", file_hash=sha256_file(p)))
        annotations.append(AnnotationRecord(annotation_id=f"ann_B_{i}", image_id=img_id, class_id=1, class_name="class_1"))

    # Flipped label sample: identical feature profile to Cluster A (fill_byte=12), but labeled as class_id 1
    p_flipped = img_dir / "flipped.png"
    p_flipped.write_bytes(make_png(width=64, height=64, fill_byte=12))
    images.append(ImageRecord(image_id="flipped", file_path="images/flipped.png", file_hash=sha256_file(p_flipped)))
    annotations.append(AnnotationRecord(annotation_id="ann_flipped", image_id="flipped", class_id=1, class_name="class_1"))

    dataset = UnifiedDataset(
        dataset_root=str(ds_dir),
        format_origin="coco",
        images=images,
        annotations=annotations,
        classes=[
            ClassInfo(class_id=0, class_name="class_0", count=5),
            ClassInfo(class_id=1, class_name="class_1", count=6),
        ],
    )

    checker = LabelFlippingCheck()
    assert checker.threat_id == "DT-2"
    assert checker.check_applicable(dataset) is True

    findings = checker.run(
        dataset=dataset,
        feature_extractor=StatisticalFeatureExtractor(),
        evidence_store=evidence_store,
        config={"k_neighbors": 5, "disagreement_threshold": 0.8},
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.threat_id == "DT-2"
    assert "Label Inconsistencies" in f.title
    assert "images/flipped.png" in f.affected_assets


def test_systematic_mislabelling_check(temp_dir: Path, make_png, evidence_store):
    """Test DT-3 detection of asymmetric directional confusion between classes."""
    ds_dir = temp_dir / "ds_systematic"
    ds_dir.mkdir()
    img_dir = ds_dir / "images"
    img_dir.mkdir()

    # Create 12 images: 6 in Class 0, 6 in Class 1
    images = []
    annotations = []

    # Class 0 images: fill_byte around 10
    for i in range(6):
        p = img_dir / f"c0_{i}.png"
        p.write_bytes(make_png(width=64, height=64, fill_byte=10 + i))
        img_id = f"c0_{i}"
        images.append(ImageRecord(image_id=img_id, file_path=f"images/{p.name}", file_hash=sha256_file(p)))
        annotations.append(AnnotationRecord(annotation_id=f"a0_{i}", image_id=img_id, class_id=0, class_name="c0"))

    # Class 1 images: 3 images fill_byte around 15 (confused with Class 0), 3 images fill_byte 220
    for i in range(6):
        p = img_dir / f"c1_{i}.png"
        fill = 15 if i < 3 else 220
        p.write_bytes(make_png(width=64, height=64, fill_byte=fill))
        img_id = f"c1_{i}"
        images.append(ImageRecord(image_id=img_id, file_path=f"images/{p.name}", file_hash=sha256_file(p)))
        annotations.append(AnnotationRecord(annotation_id=f"a1_{i}", image_id=img_id, class_id=1, class_name="c1"))

    dataset = UnifiedDataset(
        dataset_root=str(ds_dir),
        format_origin="coco",
        images=images,
        annotations=annotations,
        classes=[
            ClassInfo(class_id=0, class_name="c0", count=6),
            ClassInfo(class_id=1, class_name="c1", count=6),
        ],
    )

    checker = SystematicMislabellingCheck()
    assert checker.threat_id == "DT-3"
    assert checker.check_applicable(dataset) is True

    findings = checker.run(
        dataset=dataset,
        feature_extractor=StatisticalFeatureExtractor(),
        evidence_store=evidence_store,
        config={"asymmetry_threshold": 0.25, "min_class_samples": 3},
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.threat_id == "DT-3"
    assert "Systematic Mislabelling" in f.title


def test_ood_insertion_check(temp_dir: Path, make_png, evidence_store):
    """Test DT-5 detection of extreme statistical feature-space outliers (>3 sigma)."""
    ds_dir = temp_dir / "ds_ood"
    ds_dir.mkdir()
    img_dir = ds_dir / "images"
    img_dir.mkdir()

    images = []
    annotations = []

    # 15 uniform images in Class 0 (fill_byte around 50)
    for i in range(15):
        p = img_dir / f"norm_{i}.png"
        p.write_bytes(make_png(width=64, height=64, fill_byte=50 + (i % 2)))
        img_id = f"norm_{i}"
        images.append(ImageRecord(image_id=img_id, file_path=f"images/{p.name}", file_hash=sha256_file(p)))
        annotations.append(AnnotationRecord(annotation_id=f"a_{i}", image_id=img_id, class_id=0, class_name="c0"))

    # 1 extreme outlier image (fill_byte 255) in Class 0
    p_out = img_dir / "outlier.png"
    p_out.write_bytes(make_png(width=64, height=64, fill_byte=255))
    images.append(ImageRecord(image_id="outlier", file_path="images/outlier.png", file_hash=sha256_file(p_out)))
    annotations.append(AnnotationRecord(annotation_id="a_out", image_id="outlier", class_id=0, class_name="c0"))

    dataset = UnifiedDataset(
        dataset_root=str(ds_dir),
        format_origin="coco",
        images=images,
        annotations=annotations,
        classes=[ClassInfo(class_id=0, class_name="c0", count=16)],
    )

    checker = OODInsertionCheck()
    assert checker.threat_id == "DT-5"
    assert checker.check_applicable(dataset) is True

    findings = checker.run(
        dataset=dataset,
        feature_extractor=StatisticalFeatureExtractor(),
        evidence_store=evidence_store,
        config={"sigma_threshold": 2.0, "min_class_samples": 4},
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.threat_id == "DT-5"
    assert "Out-of-Distribution" in f.title
    assert "images/outlier.png" in f.affected_assets


def test_contributor_risk_check(temp_dir: Path, evidence_store):
    """Test DT-6 contributor provenance aggregation."""
    # Dataset without contributor provenance
    ds_no_contrib = UnifiedDataset(
        dataset_root=str(temp_dir),
        format_origin="coco",
        images=[ImageRecord(image_id="1", file_path="1.png", file_hash="h1", width=10, height=10)],
        contributor_id=None,
    )
    checker = ContributorRiskCheck()
    assert checker.threat_id == "DT-6"
    assert checker.check_applicable(ds_no_contrib) is False
    assert checker.run(ds_no_contrib) == []

    # Dataset with contributor provenance and prior findings
    ds_contrib = UnifiedDataset(
        dataset_root=str(temp_dir),
        format_origin="coco",
        images=[
            ImageRecord(image_id=f"img_{i}", file_path=f"{i}.png", file_hash=f"h{i}", width=10, height=10)
            for i in range(10)
        ],
        contributor_id="External_Vendor_Omega",
        batch_id="Batch_2026_09",
    )
    assert checker.check_applicable(ds_contrib) is True

    # Simulate 2 prior findings
    prior_findings = [
        Finding(
            asset_id=ds_contrib.asset_id,
            session_id=uuid4(),
            threat_id="DT-1",
            category="DATA_INTEGRITY",
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            title="Trigger Patch",
            description="Trigger anomaly",
        ),
        Finding(
            asset_id=ds_contrib.asset_id,
            session_id=uuid4(),
            threat_id="DT-4",
            category="DATA_INTEGRITY",
            severity=SeverityLevel.MEDIUM,
            confidence=0.8,
            title="Near-dupe",
            description="Duplicate flooding",
        ),
    ]

    findings = checker.run(
        dataset=ds_contrib,
        evidence_store=evidence_store,
        config={"prior_findings": prior_findings},
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.threat_id == "DT-6"
    assert "Contributor Risk Profile: External_Vendor_Omega" in f.title
    ev = evidence_store.get_evidence(f.evidence_ids[0])
    assert ev.metrics["total_attributed_findings"] == 2.0

