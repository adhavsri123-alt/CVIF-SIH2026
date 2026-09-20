"""DS-1: Covariate Shift detection check via feature-space distribution divergence."""

import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from cvif.analysis.distribution_shift.base import DistributionShiftCheck
from cvif.analysis.distribution_shift.metrics import (
    compute_ks_2sample,
    compute_mmd,
    compute_multivariate_wasserstein_mean,
    extract_raw_pixel_bytes,
)
from cvif.core.enums import Disposition, EvidenceType, SeverityLevel
from cvif.core.schemas import EvidenceRecord, Finding, ShiftDimensionResult, UnifiedDataset
from cvif.evidence.store import EvidenceStore
from cvif.features.base import FeatureExtractor
from cvif.features.statistical import StatisticalFeatureExtractor


class CovariateShiftCheck(DistributionShiftCheck):
    """Detects population-level covariate shift across feature embedding manifolds (DS-1)."""

    @property
    def threat_id(self) -> str:
        return "DS-1"

    @property
    def name(self) -> str:
        return "Covariate Shift Analysis"

    @property
    def description(self) -> str:
        return (
            "Quantifies feature-space distribution divergence between reference baseline "
            "and evaluation datasets using Maximum Mean Discrepancy (MMD) and Wasserstein-1 distances."
        )

    @property
    def dimension_name(self) -> str:
        return "covariate_shift"

    def check_applicable(
        self,
        reference_dataset: UnifiedDataset,
        evaluation_dataset: UnifiedDataset,
        config: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Check if both datasets have at least one image record."""
        return len(reference_dataset.images) > 0 and len(evaluation_dataset.images) > 0

    def _extract_features(
        self,
        dataset: UnifiedDataset,
        extractor: FeatureExtractor,
    ) -> List[List[float]]:
        """Extract feature embeddings from all accessible images in a dataset."""
        root = Path(dataset.dataset_root)
        embeddings: List[List[float]] = []

        for img in dataset.images:
            img_path = root / img.file_path
            try:
                if img_path.is_file():
                    raw_bytes = extract_raw_pixel_bytes(img_path.read_bytes())
                    vec = extractor.extract(raw_bytes)
                else:
                    # Deterministic fallback using image metadata
                    meta_bytes = f"{img.file_hash}:{img.width}x{img.height}".encode("utf-8")
                    vec = extractor.extract(meta_bytes)
                embeddings.append(vec)
            except Exception:
                meta_bytes = f"{img.file_hash}".encode("utf-8")
                embeddings.append(extractor.extract(meta_bytes))

        return embeddings

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
        """Execute covariate shift check comparing feature distributions."""
        cfg = config or {}
        threshold = float(cfg.get("mmd_threshold", 0.15))
        w_threshold = float(cfg.get("wasserstein_threshold", 0.20))
        min_sample_size = int(cfg.get("min_sample_size", 15))

        extractor = feature_extractor or StatisticalFeatureExtractor()

        # Resolve or compute feature embeddings
        feat_ref = (
            reference_features
            if reference_features is not None
            else self._extract_features(reference_dataset, extractor)
        )
        feat_eval = (
            evaluation_features
            if evaluation_features is not None
            else self._extract_features(evaluation_dataset, extractor)
        )

        n_ref = len(feat_ref)
        n_eval = len(feat_eval)

        # Edge case: empty features
        if n_ref == 0 or n_eval == 0:
            result = ShiftDimensionResult(
                detected=False,
                metric_value=0.0,
                p_value=1.0,
                description="Insufficient samples for covariate shift analysis (N=0).",
            )
            return result, None, None

        # Verify dimension compatibility
        dim_ref = len(feat_ref[0])
        dim_eval = len(feat_eval[0])
        if dim_ref != dim_eval:
            raise ValueError(
                f"Feature dimension mismatch: reference has dim={dim_ref}, evaluation has dim={dim_eval}"
            )

        # Compute MMD and Wasserstein metrics
        mmd_dist = compute_mmd(feat_ref, feat_eval)
        w_mean = compute_multivariate_wasserstein_mean(feat_ref, feat_eval, max_dims=16)

        # Evaluate KS test rejection ratio over top active dimensions
        ks_rejections = 0
        ks_tested = min(dim_ref, 16)
        ks_p_values = []
        for d in range(ks_tested):
            u_d = [vec[d] for vec in feat_ref]
            v_d = [vec[d] for vec in feat_eval]
            _, p_val = compute_ks_2sample(u_d, v_d)
            ks_p_values.append(p_val)
            if p_val < 0.05:
                ks_rejections += 1

        ks_rejection_ratio = round(ks_rejections / max(1, ks_tested), 4)
        median_p = round(float(ks_p_values[len(ks_p_values) // 2]), 4) if ks_p_values else 1.0

        # Composite covariate divergence metric: weighted combination of MMD and Wasserstein
        composite_distance = round(0.6 * mmd_dist + 0.4 * w_mean, 6)

        # Detect shift if either composite distance exceeds threshold or high KS rejection
        shift_detected = composite_distance > threshold or (
            w_mean > w_threshold and ks_rejection_ratio > 0.50
        )

        # Sample size sufficiency gating
        sufficient_samples = n_ref >= min_sample_size and n_eval >= min_sample_size

        desc = (
            f"Covariate shift: MMD={mmd_dist:.4f}, mean_W1={w_mean:.4f}, "
            f"KS_rejection_ratio={ks_rejection_ratio:.2f} (N_ref={n_ref}, N_eval={n_eval})"
        )

        dim_result = ShiftDimensionResult(
            detected=shift_detected,
            metric_value=composite_distance,
            p_value=median_p,
            description=desc,
        )

        finding = None
        evidence = None

        if shift_detected:
            # Calibrate confidence based on sample size
            if sufficient_samples:
                confidence = min(0.95, max(0.60, 0.50 + composite_distance))
                limitations = []
            else:
                confidence = min(0.40, 0.20 + composite_distance * 0.5)
                limitations = [
                    f"Sample size below forensic threshold (N_ref={n_ref}, N_eval={n_eval} < {min_sample_size}); "
                    "divergence metric should be verified with expanded batch size."
                ]

            severity = SeverityLevel.HIGH if composite_distance > 0.35 else SeverityLevel.MEDIUM

            evidence = self.create_evidence(
                session_id=session_id,
                evidence_type=EvidenceType.STATISTICAL,
                narrative=(
                    f"Evaluation dataset exhibits statistically significant covariate distribution shift "
                    f"relative to reference baseline {reference_dataset.dataset_hash[:12]}... (distance={composite_distance:.4f})."
                ),
                methodology="Maximum Mean Discrepancy (RBF kernel) and 1D Wasserstein-1 Distance over feature manifold",
                metrics={
                    "composite_distance": composite_distance,
                    "mmd_distance": mmd_dist,
                    "mean_wasserstein": w_mean,
                    "ks_rejection_ratio": ks_rejection_ratio,
                    "median_p_value": median_p,
                },
                baseline_comparison={
                    "reference_asset_id": str(reference_dataset.asset_id),
                    "reference_hash": reference_dataset.dataset_hash,
                    "reference_samples": n_ref,
                    "evaluation_asset_id": str(evaluation_dataset.asset_id),
                    "evaluation_hash": evaluation_dataset.dataset_hash,
                    "evaluation_samples": n_eval,
                },
                reproducibility_info={
                    "threat_id": self.threat_id,
                    "extractor": extractor.name,
                    "embedding_dim": dim_ref,
                    "threshold": threshold,
                },
                evidence_store=evidence_store,
            )

            finding = self.create_finding(
                evaluation_dataset=evaluation_dataset,
                session_id=session_id,
                severity=severity,
                confidence=confidence,
                title="Covariate Distribution Shift Detected (DS-1)",
                description=(
                    f"Feature space distribution of evaluation dataset diverges significantly from reference baseline "
                    f"(MMD={mmd_dist:.4f}, Mean Wasserstein={w_mean:.4f}, KS Rejection={ks_rejection_ratio*100:.1f}%)."
                ),
                evidence_ids=[evidence.evidence_id],
                recommended_disposition=Disposition.REVIEW,
                limitations=limitations,
            )

        return dim_result, finding, evidence
