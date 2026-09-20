"""Systematic mislabelling detection check (DT-3) evaluating asymmetric class confusion."""

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from cvif.analysis.base import DataIntegrityCheck
from cvif.core.enums import Disposition, EvidenceType, SeverityLevel
from cvif.core.schemas import Finding, UnifiedDataset
from cvif.evidence.store import EvidenceStore
from cvif.features.base import FeatureExtractor
from cvif.features.statistical import StatisticalFeatureExtractor


def compute_centroid(vectors: List[List[float]]) -> List[float]:
    """Compute mean centroid vector across a list of vectors and unit-normalize."""
    dim = len(vectors[0])
    centroid = [0.0] * dim
    for vec in vectors:
        for d in range(dim):
            centroid[d] += vec[d]
    total = len(vectors)
    centroid = [c / total for c in centroid]
    norm = sum(c * c for c in centroid) ** 0.5 or 1.0
    return [c / norm for c in centroid]


def cosine_distance(vec1: List[float], vec2: List[float]) -> float:
    dot = sum(a * b for a, b in zip(vec1, vec2))
    return max(0.0, 1.0 - dot)


class SystematicMislabellingCheck(DataIntegrityCheck):
    """Detects systematic, asymmetric mislabelling patterns across entire class pairs."""

    @property
    def threat_id(self) -> str:
        return "DT-3"

    @property
    def name(self) -> str:
        return "Systematic Mislabelling Detection"

    @property
    def description(self) -> str:
        return (
            "Analyzes global class confusion and feature distance asymmetry to identify targeted, "
            "one-directional systematic mislabelling indicative of data poisoning."
        )

    def check_applicable(self, dataset: UnifiedDataset, config: Optional[Dict[str, Any]] = None) -> bool:
        return len(dataset.images) >= 10 and len(dataset.classes) >= 2

    def run(
        self,
        dataset: UnifiedDataset,
        session_id: Optional[UUID] = None,
        feature_extractor: Optional[FeatureExtractor] = None,
        evidence_store: Optional[EvidenceStore] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        sess_id = session_id or uuid4()
        cfg = config or {}
        asymmetry_threshold = cfg.get("asymmetry_threshold", 0.35)  # Class A->B confusion >> B->A
        min_class_samples = cfg.get("min_class_samples", 3)
        extractor = feature_extractor or StatisticalFeatureExtractor()
        root = Path(dataset.dataset_root)

        findings: List[Finding] = []

        # Map images to classes
        img_to_class: Dict[str, int] = {}
        for ann in dataset.annotations:
            if ann.image_id not in img_to_class:
                img_to_class[ann.image_id] = ann.class_id

        # Group embeddings per class
        class_samples: Dict[int, List[Tuple[str, str, List[float]]]] = defaultdict(list)
        for img in dataset.images:
            c_id = img_to_class.get(img.image_id)
            if c_id is None:
                continue

            img_path = root / img.file_path
            if not img_path.is_file():
                continue

            try:
                emb = extractor.extract(img_path)
                class_samples[c_id].append((img.image_id, img.file_path, emb))
            except Exception:
                continue

        # Filter classes with sufficient samples
        active_classes = [cid for cid, s in class_samples.items() if len(s) >= min_class_samples]
        if len(active_classes) < 2:
            return []

        # Compute centroids for each class
        centroids: Dict[int, List[float]] = {
            cid: compute_centroid([emb for _, _, emb in class_samples[cid]])
            for cid in active_classes
        }

        # Measure confusion: for each sample in class A, check if closer to class B centroid than class A
        # confusion_matrix[A][B] = fraction of class A samples closer to centroid B than centroid A
        confusion_rate: Dict[Tuple[int, int], float] = {}

        for a_id in active_classes:
            samples_a = class_samples[a_id]
            centroid_a = centroids[a_id]

            for b_id in active_classes:
                if a_id == b_id:
                    continue
                centroid_b = centroids[b_id]

                # Count how many A samples are closer to centroid B
                closer_to_b = sum(
                    1 for _, _, emb in samples_a
                    if cosine_distance(emb, centroid_b) < cosine_distance(emb, centroid_a)
                )
                confusion_rate[(a_id, b_id)] = closer_to_b / len(samples_a)

        # Detect asymmetric confusion pairs: A -> B is high, but B -> A is low
        flagged_pairs: List[Dict[str, Any]] = []

        for a_id in active_classes:
            for b_id in active_classes:
                if a_id >= b_id:
                    continue

                rate_ab = confusion_rate.get((a_id, b_id), 0.0)
                rate_ba = confusion_rate.get((b_id, a_id), 0.0)
                delta = abs(rate_ab - rate_ba)

                # High rate with significant directional asymmetry
                if (rate_ab > 0.30 or rate_ba > 0.30) and delta >= asymmetry_threshold:
                    source_id, target_id = (a_id, b_id) if rate_ab > rate_ba else (b_id, a_id)
                    s_rate, t_rate = (rate_ab, rate_ba) if rate_ab > rate_ba else (rate_ba, rate_ab)

                    source_name = next((c.class_name for c in dataset.classes if c.class_id == source_id), str(source_id))
                    target_name = next((c.class_name for c in dataset.classes if c.class_id == target_id), str(target_id))

                    flagged_pairs.append({
                        "source_class_id": source_id,
                        "source_class_name": source_name,
                        "target_class_id": target_id,
                        "target_class_name": target_name,
                        "source_to_target_confusion": round(s_rate, 3),
                        "target_to_source_confusion": round(t_rate, 3),
                        "asymmetry_delta": round(delta, 3),
                        "sample_count": len(class_samples[source_id]),
                    })

        if flagged_pairs:
            pair_summaries = [f"{p['source_class_name']} -> {p['target_class_name']}" for p in flagged_pairs]

            findings.append(
                self.create_finding(
                    dataset=dataset,
                    session_id=sess_id,
                    severity=SeverityLevel.HIGH,
                    confidence=0.82,
                    title=f"Asymmetric Systematic Mislabelling Pattern ({', '.join(pair_summaries)})",
                    description=(
                        f"Detected {len(flagged_pairs)} directed class confusion anomaly. Samples of "
                        f"source class consistently cluster in target class space while target class remains distinct."
                    ),
                    evidence_type=EvidenceType.COMPARATIVE,
                    narrative=(
                        f"Found strong directional asymmetry in feature-space class boundaries: "
                        f"{flagged_pairs[0]['source_to_target_confusion']*100:.1f}% of {flagged_pairs[0]['source_class_name']} "
                        f"samples are closer to {flagged_pairs[0]['target_class_name']} centroid than their own, "
                        f"whereas the reverse is only {flagged_pairs[0]['target_to_source_confusion']*100:.1f}%. "
                        f"This pattern indicates targeted systematic mislabelling."
                    ),
                    methodology="Pairwise centroid distance confusion matrix and directional asymmetry analysis",
                    metrics={
                        "flagged_pairs_count": float(len(flagged_pairs)),
                        "max_asymmetry_delta": max(p["asymmetry_delta"] for p in flagged_pairs),
                    },
                    artifacts=None,
                    baseline_comparison={
                        "expected_directional_asymmetry": 0.05,
                        "flagged_pairs": flagged_pairs,
                    },
                    affected_assets=pair_summaries,
                    recommended_disposition=Disposition.REVIEW,
                    limitations=[
                        "Does not distinguish fine-grained subset hierarchies (e.g. 'SUV' being a subset of 'Vehicle').",
                    ],
                    evidence_store=evidence_store,
                )
            )

        return findings
