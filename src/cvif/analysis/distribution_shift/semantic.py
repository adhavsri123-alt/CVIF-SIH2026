"""DS-2: Semantic & Concept Shift detection check via class-prior and representation asymmetry."""

from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from cvif.analysis.distribution_shift.base import DistributionShiftCheck
from cvif.analysis.distribution_shift.metrics import compute_class_tv
from cvif.core.enums import Disposition, EvidenceType, SeverityLevel
from cvif.core.schemas import EvidenceRecord, Finding, ShiftDimensionResult, UnifiedDataset
from cvif.evidence.store import EvidenceStore
from cvif.features.base import FeatureExtractor


class SemanticShiftCheck(DistributionShiftCheck):
    """Detects class-prior distribution divergence and semantic concept shifts (DS-2)."""

    @property
    def threat_id(self) -> str:
        return "DS-2"

    @property
    def name(self) -> str:
        return "Semantic & Concept Shift Analysis"

    @property
    def description(self) -> str:
        return (
            "Quantifies class-prior probability shifts, label distribution asymmetry, "
            "and class omission between reference and evaluation datasets using Total Variation distance."
        )

    @property
    def dimension_name(self) -> str:
        return "semantic_shift"

    def check_applicable(
        self,
        reference_dataset: UnifiedDataset,
        evaluation_dataset: UnifiedDataset,
        config: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Applicable if either dataset contains annotations or class definitions."""
        ref_has_data = len(reference_dataset.annotations) > 0 or len(reference_dataset.classes) > 0
        eval_has_data = len(evaluation_dataset.annotations) > 0 or len(evaluation_dataset.classes) > 0
        return ref_has_data or eval_has_data

    def _get_class_counts(self, dataset: UnifiedDataset) -> Dict[str, int]:
        """Aggregate instance counts per class name from annotations and class registry."""
        counts: Dict[str, int] = Counter()

        # Build id-to-name lookup
        class_names = {c.class_id: c.class_name for c in dataset.classes}

        # Count from annotations
        for ann in dataset.annotations:
            name = ann.class_name or class_names.get(ann.class_id, f"class_{ann.class_id}")
            counts[name] += 1

        # Fallback to class count records if annotations list is empty
        if not counts and dataset.classes:
            for c in dataset.classes:
                counts[c.class_name] = c.count

        return dict(counts)

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
        """Execute semantic shift check comparing class prior distributions."""
        cfg = config or {}
        tv_threshold = float(cfg.get("class_tv_threshold", 0.25))
        min_sample_size = int(cfg.get("min_sample_size", 15))

        ref_counts = self._get_class_counts(reference_dataset)
        eval_counts = self._get_class_counts(evaluation_dataset)

        n_ref_ann = sum(ref_counts.values())
        n_eval_ann = sum(eval_counts.values())

        # Edge case: no class data available in either dataset
        if n_ref_ann == 0 and n_eval_ann == 0:
            result = ShiftDimensionResult(
                detected=False,
                metric_value=0.0,
                p_value=1.0,
                description="No class annotations available for semantic shift evaluation.",
            )
            return result, None, None

        tv_dist, details = compute_class_tv(ref_counts, eval_counts)

        missing_classes = details["missing_classes"]
        new_classes = details["new_classes"]

        # Shift is detected if TV distance exceeds threshold or known reference classes are entirely missing
        detected = tv_dist > tv_threshold or len(missing_classes) > 0

        desc = (
            f"Semantic shift: TV={tv_dist:.4f} (missing_classes={len(missing_classes)}, "
            f"new_classes={len(new_classes)}, N_ref={n_ref_ann}, N_eval={n_eval_ann})"
        )

        dim_result = ShiftDimensionResult(
            detected=detected,
            metric_value=tv_dist,
            p_value=round(max(0.0, 1.0 - tv_dist), 4),
            description=desc,
        )

        finding = None
        evidence = None

        if detected:
            sufficient_samples = n_ref_ann >= min_sample_size and n_eval_ann >= min_sample_size
            if sufficient_samples:
                confidence = min(0.95, max(0.60, 0.50 + tv_dist * 0.45))
                limitations = []
            else:
                confidence = min(0.40, 0.20 + tv_dist * 0.3)
                limitations = [
                    f"Annotation count below forensic threshold (N_ref={n_ref_ann}, N_eval={n_eval_ann} < {min_sample_size}); "
                    "observed class asymmetry may reflect sparse batch collection rather than structural prior shift."
                ]

            severity = SeverityLevel.HIGH if (tv_dist > 0.50 or len(missing_classes) > 2) else SeverityLevel.MEDIUM

            evidence = self.create_evidence(
                session_id=session_id,
                evidence_type=EvidenceType.STATISTICAL,
                narrative=(
                    f"Class frequency distribution of evaluation dataset diverges from reference baseline "
                    f"(Total Variation distance={tv_dist:.4f}). Missing classes: {missing_classes}; "
                    f"New classes: {new_classes}."
                ),
                methodology="Total Variation Distance over categorical class probability distributions",
                metrics={
                    "class_tv_distance": tv_dist,
                    "missing_class_count": float(len(missing_classes)),
                    "new_class_count": float(len(new_classes)),
                    "reference_annotation_count": float(n_ref_ann),
                    "evaluation_annotation_count": float(n_eval_ann),
                },
                baseline_comparison={
                    "reference_asset_id": str(reference_dataset.asset_id),
                    "reference_classes": list(ref_counts.keys()),
                    "evaluation_asset_id": str(evaluation_dataset.asset_id),
                    "evaluation_classes": list(eval_counts.keys()),
                    "details": details,
                },
                reproducibility_info={
                    "threat_id": self.threat_id,
                    "tv_threshold": tv_threshold,
                },
                evidence_store=evidence_store,
            )

            finding = self.create_finding(
                evaluation_dataset=evaluation_dataset,
                session_id=session_id,
                severity=severity,
                confidence=confidence,
                title="Semantic Concept / Class Prior Shift Detected (DS-2)",
                description=(
                    f"Class prior probabilities have shifted significantly from baseline (Total Variation={tv_dist:.4f}). "
                    f"Missing expected classes: {missing_classes or 'None'}. New unexpected classes: {new_classes or 'None'}."
                ),
                evidence_ids=[evidence.evidence_id],
                recommended_disposition=Disposition.REVIEW,
                limitations=limitations,
            )

        return dim_result, finding, evidence
