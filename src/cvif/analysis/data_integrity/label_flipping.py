"""Label flipping and localized label inconsistency detection check (DT-2)."""

import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from cvif.analysis.base import DataIntegrityCheck
from cvif.core.enums import Disposition, EvidenceType, SeverityLevel
from cvif.core.schemas import Finding, UnifiedDataset
from cvif.evidence.store import EvidenceStore
from cvif.features.base import FeatureExtractor
from cvif.features.statistical import StatisticalFeatureExtractor


def cosine_distance(vec1: List[float], vec2: List[float]) -> float:
    """Compute cosine distance (1 - cosine_similarity) between unit-normalized vectors."""
    dot = sum(a * b for a, b in zip(vec1, vec2))
    return max(0.0, 1.0 - dot)


class LabelFlippingCheck(DataIntegrityCheck):
    """Identifies individual samples whose assigned label severely contradicts feature-space neighborhood."""

    @property
    def threat_id(self) -> str:
        return "DT-2"

    @property
    def name(self) -> str:
        return "Label Flipping & Inconsistency Detection"

    @property
    def description(self) -> str:
        return (
            "Detects suspicious label flipping where an individual sample's declared class label "
            "contradicts the unanimous consensus of its k-nearest neighbors in feature embedding space."
        )

    def check_applicable(self, dataset: UnifiedDataset, config: Optional[Dict[str, Any]] = None) -> bool:
        return len(dataset.images) >= 6 and len(dataset.classes) >= 2

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
        k_neighbors = cfg.get("k_neighbors", 5)
        disagreement_threshold = cfg.get("disagreement_threshold", 0.8)  # 80%+ neighbors disagree
        extractor = feature_extractor or StatisticalFeatureExtractor()
        root = Path(dataset.dataset_root)

        findings: List[Finding] = []

        # Map each image_id to primary class_id
        # (For object detection datasets, pick the dominant annotated class)
        img_to_class: Dict[str, int] = {}
        for ann in dataset.annotations:
            if ann.image_id not in img_to_class:
                img_to_class[ann.image_id] = ann.class_id

        # Extract features for all images
        samples: List[Tuple[str, str, int, List[float]]] = []  # (image_id, file_path, class_id, embedding)
        for img in dataset.images:
            c_id = img_to_class.get(img.image_id)
            if c_id is None:
                continue

            img_path = root / img.file_path
            if not img_path.is_file():
                continue

            try:
                emb = extractor.extract(img_path)
                samples.append((img.image_id, img.file_path, c_id, emb))
            except Exception:
                continue

        if len(samples) < k_neighbors + 1:
            return []

        # Evaluate k-NN neighbor disagreement for each sample
        suspicious_samples: List[Dict[str, Any]] = []

        for i, (img_id, path, declared_class, emb_i) in enumerate(samples):
            # Compute distances to all other samples
            distances: List[Tuple[float, int]] = []  # (distance, neighbor_class_id)
            for j, (_, _, other_class, emb_j) in enumerate(samples):
                if i == j:
                    continue
                d = cosine_distance(emb_i, emb_j)
                distances.append((d, other_class))

            distances.sort(key=lambda x: x[0])
            top_k = distances[:k_neighbors]

            # Count votes among neighbors
            neighbor_votes: Dict[int, int] = {}
            for _, n_class in top_k:
                neighbor_votes[n_class] = neighbor_votes.get(n_class, 0) + 1

            declared_votes = neighbor_votes.get(declared_class, 0)
            disagreement_ratio = 1.0 - (declared_votes / len(top_k))

            # If disagreement exceeds threshold
            if disagreement_ratio >= disagreement_threshold:
                # Plurality predicted class
                predicted_class = max(neighbor_votes.items(), key=lambda x: x[1])[0]
                pred_name = next((c.class_name for c in dataset.classes if c.class_id == predicted_class), str(predicted_class))
                decl_name = next((c.class_name for c in dataset.classes if c.class_id == declared_class), str(declared_class))

                suspicious_samples.append({
                    "image_id": img_id,
                    "file_path": path,
                    "declared_class_id": declared_class,
                    "declared_class_name": decl_name,
                    "consensus_class_id": predicted_class,
                    "consensus_class_name": pred_name,
                    "neighbor_disagreement_ratio": round(disagreement_ratio, 3),
                    "mean_neighbor_distance": round(sum(d for d, _ in top_k) / len(top_k), 4),
                })

        if suspicious_samples:
            affected_paths = [s["file_path"] for s in suspicious_samples]
            ratio = len(suspicious_samples) / len(samples)
            confidence = min(0.95, 0.70 + (ratio * 0.5))

            findings.append(
                self.create_finding(
                    dataset=dataset,
                    session_id=sess_id,
                    severity=SeverityLevel.HIGH if ratio > 0.05 else SeverityLevel.MEDIUM,
                    confidence=confidence,
                    title=f"Potential Label Inconsistencies Detected ({len(suspicious_samples)} samples)",
                    description=(
                        f"Found {len(suspicious_samples)} sample(s) where declared label strongly disagrees "
                        f"with k-NN feature neighborhood consensus (>= {int(disagreement_threshold*100)}% disagreement)."
                    ),
                    evidence_type=EvidenceType.STATISTICAL,
                    narrative=(
                        f"Identified {len(suspicious_samples)} samples whose features consistently align with "
                        f"a different class neighborhood than their declared annotation. This indicates potential "
                        f"label flipping attack or human mislabelling error."
                    ),
                    methodology=f"Frozen feature embedding k-NN leave-one-out consensus (k={k_neighbors})",
                    metrics={
                        "inconsistent_samples_count": float(len(suspicious_samples)),
                        "inconsistent_ratio": round(ratio, 4),
                        "k_neighbors": float(k_neighbors),
                    },
                    artifacts=None,
                    baseline_comparison={
                        "expected_inconsistency_rate": 0.01,
                        "observed_inconsistency_rate": round(ratio, 4),
                        "suspicious_samples": suspicious_samples[:25],
                    },
                    affected_assets=affected_paths[:50],
                    recommended_disposition=Disposition.REVIEW,
                    limitations=[
                        "Does not prove malicious intent; genuine visual ambiguity or fine-grained classes can cause disagreement.",
                        "Accuracy depends on feature extractor representational quality.",
                    ],
                    evidence_store=evidence_store,
                )
            )

        return findings
