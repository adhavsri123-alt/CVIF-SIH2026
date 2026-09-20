"""Comprehensive unit and anti-stub tests for Phase 6 Distribution Shift Analysis."""

import math
from pathlib import Path
import time
from typing import List, Sequence
from uuid import uuid4

import pytest

from cvif.analysis.distribution_shift import (
    AdversarialManipulationCheck,
    CovariateShiftCheck,
    DistributionShiftOrchestrator,
    EnvironmentalDriftCheck,
    SemanticShiftCheck,
)
from cvif.analysis.distribution_shift.metrics import (
    compute_class_tv,
    compute_ks_2sample,
    compute_mmd,
    compute_multivariate_wasserstein_mean,
    compute_wasserstein_1d,
    extract_image_quality_scalars,
)
from cvif.core.enums import AuditEventType, Disposition, SeverityLevel
from cvif.core.schemas import (
    AnnotationRecord,
    ClassInfo,
    ImageRecord,
    ShiftReport,
    UnifiedDataset,
)
from cvif.crypto.hashing import sha256_bytes


# =====================================================================
# Dataset Generation Helpers
# =====================================================================


def create_mock_dataset(
    base_dir: Path,
    name: str,
    n_images: int = 20,
    classes: Sequence[str] = ("tank", "apc"),
    class_weights: Sequence[float] = (0.5, 0.5),
    fill_byte: int = 100,
    noise_scale: int = 0,
    make_png_fn=None,
) -> UnifiedDataset:
    """Create a physically real UnifiedDataset with PNG image files on disk."""
    ds_root = base_dir / name
    ds_root.mkdir(parents=True, exist_ok=True)
    img_dir = ds_root / "images"
    img_dir.mkdir(parents=True, exist_ok=True)

    images: List[ImageRecord] = []
    annotations: List[AnnotationRecord] = []

    cum_weights = []
    total_w = sum(class_weights)
    acc = 0.0
    for w in class_weights:
        acc += w / total_w
        cum_weights.append(acc)

    for i in range(n_images):
        img_id = f"{name}_img_{i:04d}"
        file_rel = f"images/{img_id}.png"
        img_path = ds_root / file_rel

        # Generate synthetic image bytes
        cur_fill = min(255, max(0, fill_byte + (i % 5) * noise_scale))
        if make_png_fn:
            img_bytes = make_png_fn(width=64, height=48, fill_byte=cur_fill)
        else:
            img_bytes = bytes([cur_fill]) * 200

        img_path.write_bytes(img_bytes)

        # Determine class
        ratio = (i + 0.5) / n_images
        assigned_cls_idx = 0
        for idx, cw in enumerate(cum_weights):
            if ratio <= cw:
                assigned_cls_idx = idx
                break
        cls_name = classes[assigned_cls_idx]

        images.append(
            ImageRecord(
                image_id=img_id,
                file_path=file_rel,
                file_hash=sha256_bytes(img_bytes),
                width=64,
                height=48,
                file_size_bytes=len(img_bytes),
            )
        )

        annotations.append(
            AnnotationRecord(
                annotation_id=f"ann_{img_id}",
                image_id=img_id,
                class_id=assigned_cls_idx,
                class_name=cls_name,
                bbox=[0.1, 0.1, 0.8, 0.8],
            )
        )

    class_counts = {c: 0 for c in classes}
    for a in annotations:
        class_counts[a.class_name] += 1

    class_infos = [
        ClassInfo(class_id=idx, class_name=c, count=class_counts[c])
        for idx, c in enumerate(classes)
    ]

    ds = UnifiedDataset(
        asset_id=uuid4(),
        dataset_root=str(ds_root),
        format_origin="coco",
        images=images,
        classes=class_infos,
        annotations=annotations,
    )
    ds.dataset_hash = ds.compute_dataset_hash()
    return ds


# =====================================================================
# 1. Statistical Engine Unit Tests
# =====================================================================


def test_wasserstein_1d_mathematical_properties():
    """Verify exact 1D Wasserstein distance on known analytical distributions."""
    # Identical distributions -> 0.0
    assert compute_wasserstein_1d([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]) == 0.0

    # Constant shift: U = [1, 2, 3], V = [2, 3, 4] -> W1 must be exactly 1.0
    w1 = compute_wasserstein_1d([1.0, 2.0, 3.0], [2.0, 3.0, 4.0])
    assert abs(w1 - 1.0) < 1e-6

    # Scalar point delta
    assert abs(compute_wasserstein_1d([0.0], [10.0]) - 10.0) < 1e-6

    # Empty inputs
    assert compute_wasserstein_1d([], [1.0, 2.0]) == 0.0
    assert compute_wasserstein_1d([1.0], []) == 0.0


def test_wasserstein_1d_numerical_guards():
    """Verify strict rejection of NaN and Inf values."""
    with pytest.raises(ValueError, match="non-finite"):
        compute_wasserstein_1d([1.0, float("nan")], [2.0, 3.0])

    with pytest.raises(ValueError, match="non-finite"):
        compute_wasserstein_1d([1.0, 2.0], [float("inf"), 3.0])


def test_ks_2sample_properties():
    """Verify Kolmogorov-Smirnov test on identical and disjoint distributions."""
    # Identical samples -> statistic 0, p-value 1.0
    stat, p = compute_ks_2sample([1.0, 2.0, 3.0, 4.0], [1.0, 2.0, 3.0, 4.0])
    assert stat == 0.0
    assert p == 1.0

    # Disjoint distributions -> statistic 1.0, p-value very small
    stat, p = compute_ks_2sample(list(range(20)), list(range(100, 120)))
    assert stat == 1.0
    assert p < 0.001

    # Empty inputs
    assert compute_ks_2sample([], [1.0]) == (0.0, 1.0)


def test_ks_2sample_numerical_guards():
    """Verify strict rejection of NaN and Inf in KS test."""
    with pytest.raises(ValueError, match="non-finite"):
        compute_ks_2sample([float("nan")], [1.0, 2.0])


def test_mmd_properties():
    """Verify Maximum Mean Discrepancy calculations."""
    x = [[0.1 * i for _ in range(8)] for i in range(10)]
    # Identical populations -> MMD == 0.0
    assert compute_mmd(x, x) == 0.0

    # Shifted population -> MMD > 0.0
    y = [[0.1 * i + 0.5 for _ in range(8)] for i in range(10)]
    mmd = compute_mmd(x, y)
    assert mmd > 0.05

    # Dimension mismatch
    with pytest.raises(ValueError, match="dimension mismatch|has length"):
        compute_mmd([[1.0, 2.0]], [[1.0, 2.0, 3.0]])

    # Non-finite values
    with pytest.raises(ValueError, match="non-finite"):
        compute_mmd([[1.0, float("nan")]], [[1.0, 2.0]])


def test_class_tv_properties():
    """Verify Total Variation distance over class distributions."""
    ref = {"tank": 50, "apc": 50}
    # Identical priors -> TV = 0.0
    tv, details = compute_class_tv(ref, ref)
    assert tv == 0.0
    assert len(details["missing_classes"]) == 0

    # Completely disjoint -> TV = 1.0
    eval_disjoint = {"drone": 100}
    tv, details = compute_class_tv(ref, eval_disjoint)
    assert tv == 1.0
    assert "tank" in details["missing_classes"]
    assert "apc" in details["missing_classes"]
    assert "drone" in details["new_classes"]


def test_image_quality_scalars():
    """Verify byte-level image quality scalar extraction."""
    dark_bytes = bytes([10]) * 100
    bright_bytes = bytes([240]) * 100

    q_dark = extract_image_quality_scalars(dark_bytes, 64, 48)
    q_bright = extract_image_quality_scalars(bright_bytes, 64, 48)

    assert q_dark["luminance"] < 0.10
    assert q_bright["luminance"] > 0.90
    assert q_dark["contrast"] == 0.0  # Zero variance constant fill


# =====================================================================
# 2. End-to-End Orchestrator & Threat Taxonomy Tests
# =====================================================================


def test_category_a_identical_distributions(temp_dir: Path, make_png, evidence_store, audit_logger, db_manager):
    """Category A: Identical reference and evaluation populations yield zero shift and ACCEPT."""
    ref_ds = create_mock_dataset(temp_dir, "ref_ident", n_images=20, fill_byte=100, make_png_fn=make_png)

    orchestrator = DistributionShiftOrchestrator(
        evidence_store=evidence_store,
        audit_logger=audit_logger,
        db_manager=db_manager,
    )

    report, session = orchestrator.run_analysis(ref_ds, ref_ds)

    assert report.overall_distance < 0.01
    assert report.characterization == "NO_SIGNIFICANT_SHIFT"
    assert report.assessment.evidence_sufficient is True
    assert report.assessment.natural_drift_likelihood == 0.05
    assert report.assessment.suspicious_manipulation_likelihood == 0.05
    assert len(session.findings) == 0

    # Ensure ShiftReport artifact was persisted
    report_file = temp_dir / "evidence_store" / "sessions" / str(session.session_id) / "artifacts" / "shift_report.json"
    assert report_file.is_file()


def test_category_b_covariate_shift(temp_dir: Path, make_png, evidence_store):
    """Category B: Feature distribution shift (DS-1) detected under strong visual differences."""
    ref_ds = create_mock_dataset(temp_dir, "ref_cov", n_images=20, fill_byte=30, make_png_fn=make_png)
    eval_ds = create_mock_dataset(temp_dir, "eval_cov", n_images=20, fill_byte=220, make_png_fn=make_png)

    check = CovariateShiftCheck()
    dim_res, finding, evidence = check.run(
        reference_dataset=ref_ds,
        evaluation_dataset=eval_ds,
        session_id=uuid4(),
        evidence_store=evidence_store,
    )

    assert dim_res.detected is True
    assert dim_res.metric_value > 0.15
    assert finding is not None
    assert finding.threat_id == "DS-1"
    assert finding.category == "DISTRIBUTION_SHIFT"
    assert finding.recommended_disposition == Disposition.REVIEW
    assert evidence is not None


def test_category_c_semantic_shift(temp_dir: Path, make_png, evidence_store):
    """Category C: Class-prior distribution shift (DS-2) detected under skewed prevalence."""
    # Reference has equal classes: 50% tank, 50% apc
    ref_ds = create_mock_dataset(
        temp_dir, "ref_sem", n_images=20, classes=("tank", "apc"), class_weights=(0.5, 0.5), make_png_fn=make_png
    )
    # Evaluation has skewed classes: 100% tank, 0% apc
    eval_ds = create_mock_dataset(
        temp_dir, "eval_sem", n_images=20, classes=("tank", "apc"), class_weights=(1.0, 0.0), make_png_fn=make_png
    )

    check = SemanticShiftCheck()
    dim_res, finding, evidence = check.run(
        reference_dataset=ref_ds,
        evaluation_dataset=eval_ds,
        session_id=uuid4(),
        evidence_store=evidence_store,
    )

    assert dim_res.detected is True
    assert dim_res.metric_value >= 0.50  # Half the distribution shifted
    assert finding is not None
    assert finding.threat_id == "DS-2"
    assert "Semantic Concept / Class Prior Shift" in finding.title
    assert "apc" in finding.description or "missing" in finding.description.lower()


def test_category_d_environmental_drift(temp_dir: Path, make_png, evidence_store):
    """Category D: Sensor / environmental degradation drift (DS-3) detected."""
    ref_ds = create_mock_dataset(temp_dir, "ref_env", n_images=20, fill_byte=50, make_png_fn=make_png)
    eval_ds = create_mock_dataset(temp_dir, "eval_env", n_images=20, fill_byte=220, make_png_fn=make_png)

    check = EnvironmentalDriftCheck()
    dim_res, finding, evidence = check.run(
        reference_dataset=ref_ds,
        evaluation_dataset=eval_ds,
        session_id=uuid4(),
        evidence_store=evidence_store,
    )

    assert dim_res.detected is True
    assert dim_res.metric_value > 0.20
    assert finding is not None
    assert finding.threat_id == "DS-3"
    assert "Environmental / Sensor Quality Degradation" in finding.title


def test_category_e_targeted_manipulation(temp_dir: Path, make_png, evidence_store):
    """Category E: Targeted subpopulation manipulation (DS-4) detected with QUARANTINE disposition."""
    ref_ds = create_mock_dataset(
        temp_dir, "ref_manip", n_images=20, classes=("tank", "apc"), class_weights=(0.5, 0.5), fill_byte=100, make_png_fn=make_png
    )

    # In eval dataset, APC is identical (fill 100), but TANK is heavily perturbed (fill 250)
    eval_ds = create_mock_dataset(
        temp_dir, "eval_manip", n_images=20, classes=("tank", "apc"), class_weights=(0.5, 0.5), fill_byte=100, make_png_fn=make_png
    )
    # Mutate only tank images
    for idx, ann in enumerate(eval_ds.annotations):
        if ann.class_name == "tank":
            img_p = Path(eval_ds.dataset_root) / eval_ds.images[idx].file_path
            new_bytes = make_png(width=64, height=48, fill_byte=250)
            img_p.write_bytes(new_bytes)
            eval_ds.images[idx].file_hash = sha256_bytes(new_bytes)

    check = AdversarialManipulationCheck()
    dim_res, finding, evidence = check.run(
        reference_dataset=ref_ds,
        evaluation_dataset=eval_ds,
        session_id=uuid4(),
        evidence_store=evidence_store,
    )

    assert dim_res.detected is True
    assert finding is not None
    assert finding.threat_id == "DS-4"
    assert finding.recommended_disposition == Disposition.QUARANTINE
    assert finding.severity == SeverityLevel.HIGH


def test_category_f_small_sample_gating(temp_dir: Path, make_png, evidence_store):
    """Category F: N < 15 samples marked evidence_sufficient=False without crashing."""
    ref_small = create_mock_dataset(temp_dir, "ref_small", n_images=5, fill_byte=50, make_png_fn=make_png)
    eval_small = create_mock_dataset(temp_dir, "eval_small", n_images=5, fill_byte=200, make_png_fn=make_png)

    orchestrator = DistributionShiftOrchestrator(evidence_store=evidence_store)
    report, session = orchestrator.run_analysis(ref_small, eval_small)

    assert report.assessment.evidence_sufficient is False
    assert report.characterization == "INSUFFICIENT_SAMPLES"
    assert report.assessment.natural_drift_likelihood <= 0.40
    assert report.assessment.suspicious_manipulation_likelihood <= 0.40
    assert "insufficient" in report.assessment.reasoning.lower()


def test_category_g_n15_boundary(temp_dir: Path, make_png, evidence_store):
    """Category G: Exact N = 15 sample size boundary marks evidence_sufficient=True."""
    ref_15 = create_mock_dataset(temp_dir, "ref_15", n_images=15, fill_byte=100, make_png_fn=make_png)
    eval_15 = create_mock_dataset(temp_dir, "eval_15", n_images=15, fill_byte=100, make_png_fn=make_png)

    orchestrator = DistributionShiftOrchestrator(evidence_store=evidence_store)
    report, session = orchestrator.run_analysis(ref_15, eval_15)

    assert report.assessment.evidence_sufficient is True


def test_category_h_i_empty_datasets(temp_dir: Path, evidence_store):
    """Categories H & I: Empty reference or evaluation datasets handled safely."""
    empty_ds = UnifiedDataset(
        asset_id=uuid4(),
        dataset_root=str(temp_dir / "empty"),
        format_origin="coco",
        images=[],
        classes=[],
        annotations=[],
    )
    non_empty = UnifiedDataset(
        asset_id=uuid4(),
        dataset_root=str(temp_dir / "non_empty"),
        format_origin="coco",
        images=[ImageRecord(image_id="1", file_path="dummy.png", file_hash="0"*64)],
        classes=[],
        annotations=[],
    )

    orchestrator = DistributionShiftOrchestrator(evidence_store=evidence_store)
    report, session = orchestrator.run_analysis(empty_ds, non_empty)

    assert report.overall_distance == 0.0
    assert report.assessment.evidence_sufficient is False


def test_category_j_k_constant_zero_variance(temp_dir: Path, make_png, evidence_store):
    """Categories J & K: Constant byte streams (zero variance) regularized without division error."""
    # All pixels byte 128
    ref_const = create_mock_dataset(temp_dir, "ref_const", n_images=15, fill_byte=128, make_png_fn=make_png)
    eval_const = create_mock_dataset(temp_dir, "eval_const", n_images=15, fill_byte=128, make_png_fn=make_png)

    orchestrator = DistributionShiftOrchestrator(evidence_store=evidence_store)
    report, session = orchestrator.run_analysis(ref_const, eval_const)

    assert report.overall_distance < 0.01
    assert report.characterization == "NO_SIGNIFICANT_SHIFT"


def test_category_l_m_missing_and_new_classes(temp_dir: Path, make_png, evidence_store):
    """Categories L & M: Missing and new classes tracked in semantic shift details."""
    ref_ds = create_mock_dataset(temp_dir, "ref_cls", n_images=16, classes=("tank", "apc"), make_png_fn=make_png)
    eval_ds = create_mock_dataset(temp_dir, "eval_cls", n_images=16, classes=("apc", "radar"), make_png_fn=make_png)

    check = SemanticShiftCheck()
    dim_res, finding, evidence = check.run(ref_ds, eval_ds, session_id=uuid4(), evidence_store=evidence_store)

    assert dim_res.detected is True
    assert evidence is not None
    details = evidence.baseline_comparison.get("details", {})
    assert "tank" in details["missing_classes"]
    assert "radar" in details["new_classes"]


def test_category_p_deterministic_repeatability(temp_dir: Path, make_png, evidence_store):
    """Category P: Repeated evaluation on identical inputs produces identical results."""
    ds1 = create_mock_dataset(temp_dir, "ds1_det", n_images=16, fill_byte=80, make_png_fn=make_png)
    ds2 = create_mock_dataset(temp_dir, "ds2_det", n_images=16, fill_byte=160, make_png_fn=make_png)

    orchestrator = DistributionShiftOrchestrator(evidence_store=evidence_store)

    report1, _ = orchestrator.run_analysis(ds1, ds2)
    report2, _ = orchestrator.run_analysis(ds1, ds2)

    assert report1.overall_distance == report2.overall_distance
    assert report1.assessment.natural_drift_likelihood == report2.assessment.natural_drift_likelihood
    assert report1.assessment.suspicious_manipulation_likelihood == report2.assessment.suspicious_manipulation_likelihood


def test_category_r_audit_trail_chaining(temp_dir: Path, make_png, evidence_store, audit_logger, db_manager):
    """Category R: Audit logging integration maintains unbroken cryptographic chain."""
    ref_ds = create_mock_dataset(temp_dir, "ref_audit", n_images=15, fill_byte=50, make_png_fn=make_png)
    eval_ds = create_mock_dataset(temp_dir, "eval_audit", n_images=15, fill_byte=200, make_png_fn=make_png)

    orchestrator = DistributionShiftOrchestrator(
        evidence_store=evidence_store,
        audit_logger=audit_logger,
        db_manager=db_manager,
    )

    report, session = orchestrator.run_analysis(ref_ds, eval_ds)

    events = audit_logger.read_all_events()
    event_types = [e.event_type for e in events]

    assert AuditEventType.ANALYSIS_STARTED in event_types
    assert AuditEventType.ANALYSIS_COMPLETED in event_types

    verify_res = audit_logger.verify_chain()
    assert verify_res.is_valid is True
    assert verify_res.error_message is None


def test_category_s_air_gap_isolation(temp_dir: Path, make_png, air_gap_enforcer, evidence_store):
    """Category S: Verification that entire Phase 6 runs with zero external socket connections."""
    ref_ds = create_mock_dataset(temp_dir, "ref_ag", n_images=15, fill_byte=60, make_png_fn=make_png)
    eval_ds = create_mock_dataset(temp_dir, "eval_ag", n_images=15, fill_byte=180, make_png_fn=make_png)

    orchestrator = DistributionShiftOrchestrator(evidence_store=evidence_store)
    report, session = orchestrator.run_analysis(ref_ds, eval_ds)

    assert report.overall_distance > 0.0


def test_category_t_performance_benchmark(temp_dir: Path, make_png):
    """Category T: 50 evaluation samples vs 50 reference samples completes in < 2.0 seconds on CPU."""
    ref_ds = create_mock_dataset(temp_dir, "ref_perf", n_images=50, fill_byte=80, make_png_fn=make_png)
    eval_ds = create_mock_dataset(temp_dir, "eval_perf", n_images=50, fill_byte=160, make_png_fn=make_png)

    orchestrator = DistributionShiftOrchestrator()

    t0 = time.perf_counter()
    report, session = orchestrator.run_analysis(ref_ds, eval_ds)
    elapsed = time.perf_counter() - t0

    assert elapsed < 2.0, f"Analysis took {elapsed:.3f}s, expected < 2.0s"
    assert session.duration_ms > 0.0


# =====================================================================
# 3. Anti-Stub Dynamic Sensitivity Tests
# =====================================================================


def test_anti_stub_dynamic_response_to_inputs(temp_dir: Path, make_png):
    """Anti-Stub: Changing the evaluation dataset dynamically alters the computed distance metrics."""
    ref_ds = create_mock_dataset(temp_dir, "as_ref", n_images=15, fill_byte=50, make_png_fn=make_png)
    eval_mild = create_mock_dataset(temp_dir, "as_mild", n_images=15, fill_byte=90, make_png_fn=make_png)
    eval_severe = create_mock_dataset(temp_dir, "as_severe", n_images=15, fill_byte=220, make_png_fn=make_png)

    orchestrator = DistributionShiftOrchestrator()

    rep_mild, _ = orchestrator.run_analysis(ref_ds, eval_mild)
    rep_severe, _ = orchestrator.run_analysis(ref_ds, eval_severe)

    # Mild shift distance must be strictly less than severe shift distance
    assert rep_mild.overall_distance < rep_severe.overall_distance
    assert rep_mild.overall_distance > 0.0
    assert rep_severe.overall_distance > 0.0


def test_anti_stub_no_random_outputs(temp_dir: Path, make_png):
    """Anti-Stub: Verifies that no pseudo-randomness is used; distance metrics are bit-exact."""
    ref_ds = create_mock_dataset(temp_dir, "as_rand_ref", n_images=15, fill_byte=100, make_png_fn=make_png)
    eval_ds = create_mock_dataset(temp_dir, "as_rand_eval", n_images=15, fill_byte=180, make_png_fn=make_png)

    orchestrator = DistributionShiftOrchestrator()

    results = [orchestrator.run_analysis(ref_ds, eval_ds)[0].overall_distance for _ in range(5)]
    assert len(set(results)) == 1, "Non-deterministic output detected across runs!"
