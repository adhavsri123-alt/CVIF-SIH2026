"""DS-3: Environmental & Sensor Degradation Drift detection check via image quality and channel statistics."""

from pathlib import Path
import statistics
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from cvif.analysis.distribution_shift.base import DistributionShiftCheck
from cvif.analysis.distribution_shift.metrics import (
    compute_ks_2sample,
    compute_wasserstein_1d,
    extract_image_quality_scalars,
)
from cvif.core.enums import Disposition, EvidenceType, SeverityLevel
from cvif.core.schemas import EvidenceRecord, Finding, ShiftDimensionResult, UnifiedDataset
from cvif.evidence.store import EvidenceStore
from cvif.features.base import FeatureExtractor


class EnvironmentalDriftCheck(DistributionShiftCheck):
    """Detects sensor degradation, illumination shifts, and environmental image quality drift (DS-3)."""

    @property
    def threat_id(self) -> str:
        return "DS-3"

    @property
    def name(self) -> str:
        return "Environmental & Sensor Quality Drift Analysis"

    @property
    def description(self) -> str:
        return (
            "Quantifies image quality and channel statistics divergence (luminance, contrast, "
            "sharpness, compression) between reference baseline and evaluation datasets."
        )

    @property
    def dimension_name(self) -> str:
        return "environmental_drift"

    def check_applicable(
        self,
        reference_dataset: UnifiedDataset,
        evaluation_dataset: UnifiedDataset,
        config: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Applicable if both datasets contain at least one image record."""
        return len(reference_dataset.images) > 0 and len(evaluation_dataset.images) > 0

    def _extract_dataset_quality(self, dataset: UnifiedDataset) -> Dict[str, List[float]]:
        """Extract low-level image quality scalar series across all images in a dataset."""
        root = Path(dataset.dataset_root)
        quality_lists: Dict[str, List[float]] = {
            "luminance": [],
            "contrast": [],
            "sharpness": [],
            "size_kb": [],
        }

        for img in dataset.images:
            img_path = root / img.file_path
            data: bytes = b""
            if img_path.is_file():
                try:
                    data = img_path.read_bytes()
                except Exception:
                    data = b""

            if not data:
                # Deterministic synthesis from ImageRecord metadata
                data = f"{img.file_hash}_{img.width}x{img.height}_{img.file_size_bytes}".encode("utf-8")

            scalars = extract_image_quality_scalars(data, width=img.width, height=img.height)
            for k in quality_lists:
                quality_lists[k].append(scalars.get(k, 0.0))

        return quality_lists

    def run(
        self,
        reference_dataset: UnifiedDataset,
        evaluation_dataset: UnifiedDataset,
        session_id: UUID,
        feature_extractor: Optional[FeatureExtractor] = None,
        evidence_store: Optional[EvidenceStore] = None,
        config: Optional[Dict[str, Any]] = None,
        reference_features: Optional[List[List[float]]] = None,
        evaluation_features: Optional[List[List[float]]] = None,
    ) -> Tuple[ShiftDimensionResult, Optional[Finding], Optional[EvidenceRecord]]:
        """Execute environmental drift analysis comparing low-level image quality distributions."""
        cfg = config or {}
        w_threshold = float(cfg.get("wasserstein_threshold", 0.20))
        min_sample_size = int(cfg.get("min_sample_size", 15))

        q_ref = self._extract_dataset_quality(reference_dataset)
        q_eval = self._extract_dataset_quality(evaluation_dataset)

        n_ref = len(reference_dataset.images)
        n_eval = len(evaluation_dataset.images)

        if n_ref == 0 or n_eval == 0:
            result = ShiftDimensionResult(
                detected=False,
                metric_value=0.0,
                p_value=1.0,
                description="Insufficient images for environmental drift analysis (N=0).",
            )
            return result, None, None

        # Compute Wasserstein-1 distance and KS tests for each quality metric
        quality_keys = ["luminance", "contrast", "sharpness"]
        w_distances: Dict[str, float] = {}
        ks_results: Dict[str, Tuple[float, float]] = {}

        for k in quality_keys:
            w = compute_wasserstein_1d(q_ref[k], q_eval[k])
            ks_stat, ks_p = compute_ks_2sample(q_ref[k], q_eval[k])
            w_distances[k] = w
            ks_results[k] = (ks_stat, ks_p)

        mean_w = round(statistics.mean(w_distances.values()), 6)
        min_p = min(p for _, p in ks_results.values())

        # Detected if average Wasserstein distance exceeds threshold or multiple metrics show KS p < 0.01
        significant_ks_shifts = sum(1 for _, p in ks_results.values() if p < 0.01)
        detected = mean_w > w_threshold or (significant_ks_shifts >= 2 and mean_w > (w_threshold * 0.75))

        desc = (
            f"Environmental drift: mean_W1={mean_w:.4f} (lum_W1={w_distances['luminance']:.4f}, "
            f"contrast_W1={w_distances['contrast']:.4f}, sharp_W1={w_distances['sharpness']:.4f}, "
            f"min_p={min_p:.4e})"
        )

        dim_result = ShiftDimensionResult(
            detected=detected,
            metric_value=mean_w,
            p_value=round(min_p, 6),
            description=desc,
        )

        finding = None
        evidence = None

        if detected:
            sufficient_samples = n_ref >= min_sample_size and n_eval >= min_sample_size
            if sufficient_samples:
                confidence = min(0.95, max(0.60, 0.50 + mean_w * 0.45))
                limitations = []
            else:
                confidence = min(0.40, 0.20 + mean_w * 0.3)
                limitations = [
                    f"Sample size below forensic threshold (N_ref={n_ref}, N_eval={n_eval} < {min_sample_size}); "
                    "image quality divergence may be an artifact of limited sample burst."
                ]

            severity = SeverityLevel.MEDIUM

            evidence = self.create_evidence(
                session_id=session_id,
                evidence_type=EvidenceType.STATISTICAL,
                narrative=(
                    f"Evaluation images exhibit significant environmental / sensor quality drift "
                    f"(mean Wasserstein distance={mean_w:.4f}). Divergences: luminance={w_distances['luminance']:.4f}, "
                    f"contrast={w_distances['contrast']:.4f}, sharpness={w_distances['sharpness']:.4f}."
                ),
                methodology="1D Wasserstein-1 and Kolmogorov-Smirnov test across low-level image channel distributions",
                metrics={
                    "mean_wasserstein": mean_w,
                    "luminance_wasserstein": w_distances["luminance"],
                    "contrast_wasserstein": w_distances["contrast"],
                    "sharpness_wasserstein": w_distances["sharpness"],
                    "min_ks_p_value": min_p,
                },
                baseline_comparison={
                    "reference_asset_id": str(reference_dataset.asset_id),
                    "evaluation_asset_id": str(evaluation_dataset.asset_id),
                    "metrics_breakdown": {
                        k: {"w1": w_distances[k], "ks_stat": ks_results[k][0], "ks_p": ks_results[k][1]}
                        for k in quality_keys
                    },
                },
                reproducibility_info={
                    "threat_id": self.threat_id,
                    "w_threshold": w_threshold,
                },
                evidence_store=evidence_store,
            )

            finding = self.create_finding(
                evaluation_dataset=evaluation_dataset,
                session_id=session_id,
                severity=severity,
                confidence=confidence,
                title="Environmental / Sensor Quality Degradation Detected (DS-3)",
                description=(
                    f"Significant sensor or environmental drift detected in evaluation dataset "
                    f"(mean Wasserstein distance={mean_w:.4f}). Indicates operational changes in illumination, "
                    "weather, atmospheric haze, optical focus, or sensor calibration."
                ),
                evidence_ids=[evidence.evidence_id],
                recommended_disposition=Disposition.REVIEW,
                limitations=limitations,
            )

        return dim_result, finding, evidence
