"""DS-4: Adversarial Distribution Manipulation detection check via targeted subpopulation analysis."""

import math
from pathlib import Path
import statistics
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from cvif.analysis.distribution_shift.base import DistributionShiftCheck
from cvif.analysis.distribution_shift.metrics import extract_raw_pixel_bytes
from cvif.core.enums import Disposition, EvidenceType, SeverityLevel
from cvif.core.schemas import EvidenceRecord, Finding, ShiftDimensionResult, UnifiedDataset
from cvif.evidence.store import EvidenceStore
from cvif.features.base import FeatureExtractor
from cvif.features.statistical import StatisticalFeatureExtractor


class AdversarialManipulationCheck(DistributionShiftCheck):
    """Detects targeted subpopulation shifts and malicious distribution tampering (DS-4)."""

    @property
    def threat_id(self) -> str:
        return "DS-4"

    @property
    def name(self) -> str:
        return "Adversarial Distribution Manipulation Analysis"

    @property
    def description(self) -> str:
        return (
            "Detects targeted subpopulation poisoning, isolated cluster displacement, "
            "and malicious distribution manipulation distinguished from broad operational drift."
        )

    @property
    def dimension_name(self) -> str:
        return "adversarial_manipulation"

    def check_applicable(
        self,
        reference_dataset: UnifiedDataset,
        evaluation_dataset: UnifiedDataset,
        config: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Applicable if both datasets contain at least one image record."""
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
                    meta_bytes = f"{img.file_hash}:{img.width}x{img.height}".encode("utf-8")
                    vec = extractor.extract(meta_bytes)
                embeddings.append(vec)
            except Exception:
                meta_bytes = f"{img.file_hash}".encode("utf-8")
                embeddings.append(extractor.extract(meta_bytes))

        return embeddings

    def _map_images_to_classes(self, dataset: UnifiedDataset) -> Dict[int, str]:
        """Map image index in dataset.images to its primary annotated class name."""
        # Create image_id -> list of class names
        class_lookup = {c.class_id: c.class_name for c in dataset.classes}
        img_id_to_class: Dict[str, str] = {}

        for ann in dataset.annotations:
            if ann.image_id not in img_id_to_class:
                name = ann.class_name or class_lookup.get(ann.class_id, f"class_{ann.class_id}")
                img_id_to_class[ann.image_id] = name

        # Map index -> class
        index_to_class: Dict[int, str] = {}
        for idx, img in enumerate(dataset.images):
            c_name = img_id_to_class.get(img.image_id, "default_class")
            index_to_class[idx] = c_name

        return index_to_class

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
        """Execute subpopulation divergence analysis to detect targeted manipulation."""
        cfg = config or {}
        manip_threshold = float(cfg.get("manipulation_threshold", 0.25))
        min_sample_size = int(cfg.get("min_sample_size", 15))

        extractor = feature_extractor or StatisticalFeatureExtractor()

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

        if n_ref == 0 or n_eval == 0:
            result = ShiftDimensionResult(
                detected=False,
                metric_value=0.0,
                p_value=1.0,
                description="Insufficient samples for subpopulation manipulation analysis (N=0).",
            )
            return result, None, None

        dim = len(feat_ref[0])
        ref_img_classes = self._map_images_to_classes(reference_dataset)
        eval_img_classes = self._map_images_to_classes(evaluation_dataset)

        # Group feature vectors by class
        ref_by_class: Dict[str, List[List[float]]] = {}
        for idx, vec in enumerate(feat_ref):
            c = ref_img_classes.get(idx, "default_class")
            ref_by_class.setdefault(c, []).append(vec)

        eval_by_class: Dict[str, List[List[float]]] = {}
        for idx, vec in enumerate(feat_eval):
            c = eval_img_classes.get(idx, "default_class")
            eval_by_class.setdefault(c, []).append(vec)

        common_classes = sorted(list(set(ref_by_class.keys()) & set(eval_by_class.keys())))

        class_shifts: Dict[str, float] = {}
        if common_classes and len(common_classes) > 1:
            # Multi-class subpopulation shift analysis
            for c in common_classes:
                r_vecs = ref_by_class[c]
                e_vecs = eval_by_class[c]

                # Compute centroid of each class
                c_ref = [sum(v[d] for v in r_vecs) / len(r_vecs) for d in range(dim)]
                c_eval = [sum(v[d] for v in e_vecs) / len(e_vecs) for d in range(dim)]

                # Euclidean distance between class centroids
                dist = math.sqrt(sum((a - b) ** 2 for a, b in zip(c_ref, c_eval)))
                class_shifts[c] = dist

            shifts = list(class_shifts.values())
            mean_shift = statistics.mean(shifts)
            max_shift = max(shifts)
            std_shift = statistics.stdev(shifts) if len(shifts) > 1 else 0.0

            # Concentration ratio: max shift relative to mean shift
            concentration_ratio = max_shift / max(1e-6, mean_shift)

            # High concentration ratio indicates isolated class perturbation
            manip_score = round(min(1.0, max(0.0, (concentration_ratio - 1.0) * 0.4 + max_shift * 0.6)), 6)
            targeted_classes = [c for c, s in class_shifts.items() if s > (mean_shift + 1.5 * std_shift)]
        else:
            # Single class or unannotated: evaluate feature distance distribution bimodality
            # Compute global centroid shift
            c_ref = [sum(v[d] for v in feat_ref) / n_ref for d in range(dim)]
            c_eval = [sum(v[d] for v in feat_eval) / n_eval for d in range(dim)]
            global_dist = math.sqrt(sum((a - b) ** 2 for a, b in zip(c_ref, c_eval)))

            # Distance of each eval sample from ref centroid
            dists = [math.sqrt(sum((v[d] - c_ref[d]) ** 2 for d in range(dim))) for v in feat_eval]
            if len(dists) > 1:
                q50 = statistics.median(dists)
                q90 = sorted(dists)[int(0.9 * len(dists))]
                spread_ratio = q90 / max(1e-6, q50)
                manip_score = round(min(1.0, max(0.0, (spread_ratio - 1.2) * 0.3 + global_dist * 0.5)), 6)
            else:
                manip_score = round(min(1.0, global_dist), 6)
            targeted_classes = []
            concentration_ratio = 1.0
            mean_shift = global_dist
            max_shift = global_dist

        # Detection logic: high manipulation score indicates suspicious targeted displacement
        detected = manip_score > manip_threshold and (max_shift > 0.10 or concentration_ratio >= 1.8)

        desc = (
            f"Adversarial manipulation: score={manip_score:.4f}, concentration_ratio={concentration_ratio:.2f}, "
            f"max_shift={max_shift:.4f}, mean_shift={mean_shift:.4f}"
        )

        dim_result = ShiftDimensionResult(
            detected=detected,
            metric_value=manip_score,
            p_value=round(max(0.0, 1.0 - manip_score), 4),
            description=desc,
        )

        finding = None
        evidence = None

        if detected:
            sufficient_samples = n_ref >= min_sample_size and n_eval >= min_sample_size
            if sufficient_samples:
                confidence = min(0.95, max(0.65, 0.55 + manip_score * 0.40))
                limitations = []
            else:
                confidence = min(0.40, 0.20 + manip_score * 0.25)
                limitations = [
                    f"Sample size below forensic threshold (N_ref={n_ref}, N_eval={n_eval} < {min_sample_size}); "
                    "cannot definitively rule out small-sample clustering variance."
                ]

            severity = SeverityLevel.HIGH

            evidence = self.create_evidence(
                session_id=session_id,
                evidence_type=EvidenceType.BEHAVIORAL,
                narrative=(
                    f"Evaluation dataset displays asymmetrical subpopulation divergence consistent with "
                    f"targeted manipulation or selective poisoning (manipulation_score={manip_score:.4f}, "
                    f"concentration_ratio={concentration_ratio:.2f}). Targeted classes: {targeted_classes}."
                ),
                methodology="Subpopulation centroid divergence, dispersion asymmetry, and concentration ratio analysis",
                metrics={
                    "manipulation_score": manip_score,
                    "concentration_ratio": round(concentration_ratio, 4),
                    "max_subpopulation_shift": round(max_shift, 4),
                    "mean_subpopulation_shift": round(mean_shift, 4),
                },
                baseline_comparison={
                    "reference_asset_id": str(reference_dataset.asset_id),
                    "evaluation_asset_id": str(evaluation_dataset.asset_id),
                    "class_shifts": {c: round(s, 4) for c, s in class_shifts.items()},
                    "targeted_classes": targeted_classes,
                },
                reproducibility_info={
                    "threat_id": self.threat_id,
                    "manip_threshold": manip_threshold,
                },
                evidence_store=evidence_store,
            )

            finding = self.create_finding(
                evaluation_dataset=evaluation_dataset,
                session_id=session_id,
                severity=severity,
                confidence=confidence,
                title="Suspicious Distribution Manipulation Detected (DS-4)",
                description=(
                    f"Asymmetrical subpopulation shift detected (manipulation score={manip_score:.4f}, "
                    f"concentration ratio={concentration_ratio:.2f}). Subpopulation divergence is concentrated "
                    f"in specific clusters/classes: {targeted_classes or 'isolated feature cluster'}."
                ),
                evidence_ids=[evidence.evidence_id],
                recommended_disposition=Disposition.QUARANTINE,
                limitations=limitations,
                affected_assets=targeted_classes,
            )

        return dim_result, finding, evidence
