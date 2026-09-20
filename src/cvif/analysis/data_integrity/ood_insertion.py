"""Out-of-distribution (OOD) sample insertion detection check (DT-5)."""

from collections import defaultdict
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


class OODInsertionCheck(DataIntegrityCheck):
    """Identifies potential out-of-distribution (OOD) samples inserted into training sets."""

    @property
    def threat_id(self) -> str:
        return "DT-5"

    @property
    def name(self) -> str:
        return "Out-of-Distribution (OOD) Sample Insertion Detection"

    @property
    def description(self) -> str:
        return (
            "Detects statistical feature-space anomalies where individual samples diverge severely "
            "(> 3.0 standard deviations) from the empirical distribution of their assigned class."
        )

    def check_applicable(self, dataset: UnifiedDataset, config: Optional[Dict[str, Any]] = None) -> bool:
        return len(dataset.images) >= 6

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
        sigma_threshold = cfg.get("sigma_threshold", 3.0)  # Z-score outlier threshold
        min_class_samples = cfg.get("min_class_samples", 4)
        extractor = feature_extractor or StatisticalFeatureExtractor()
        root = Path(dataset.dataset_root)

        findings: List[Finding] = []

        # Map images to classes
        img_to_class: Dict[str, int] = {}
        for ann in dataset.annotations:
            if ann.image_id not in img_to_class:
                img_to_class[ann.image_id] = ann.class_id

        # Extract embeddings and group by class
        class_samples: Dict[int, List[Tuple[str, str, List[float]]]] = defaultdict(list)
        for img in dataset.images:
            c_id = img_to_class.get(img.image_id, 0)
            img_path = root / img.file_path
            if not img_path.is_file():
                continue

            try:
                emb = extractor.extract(img_path)
                class_samples[c_id].append((img.image_id, img.file_path, emb))
            except Exception:
                continue

        ood_candidates: List[Dict[str, Any]] = []

        for c_id, samples in class_samples.items():
            if len(samples) < min_class_samples:
                continue

            dim = len(samples[0][2])
            n = len(samples)

            # Compute per-dimension mean and variance
            means = [sum(s[2][d] for s in samples) / n for d in range(dim)]
            variances = [
                sum((s[2][d] - means[d]) ** 2 for s in samples) / max(1, n - 1)
                for d in range(dim)
            ]
            active_dims = [d for d in range(dim) if variances[d] > 1e-8]
            if not active_dims:
                continue

            std_devs = {d: math.sqrt(variances[d]) for d in active_dims}

            # Compute standardized distance for each sample across active dimensions
            for img_id, path, emb in samples:
                normalized_z = math.sqrt(
                    sum(((emb[d] - means[d]) / std_devs[d]) ** 2 for d in active_dims) / len(active_dims)
                )

                if normalized_z > sigma_threshold:
                    c_name = next((c.class_name for c in dataset.classes if c.class_id == c_id), str(c_id))
                    ood_candidates.append({
                        "image_id": img_id,
                        "file_path": path,
                        "class_id": c_id,
                        "class_name": c_name,
                        "z_dispersion_score": round(normalized_z, 3),
                    })

        if ood_candidates:
            affected_paths = [c["file_path"] for c in ood_candidates]
            ratio = len(ood_candidates) / len(dataset.images)
            confidence = min(0.85, 0.60 + (ratio * 0.4))

            findings.append(
                self.create_finding(
                    dataset=dataset,
                    session_id=sess_id,
                    severity=SeverityLevel.MEDIUM,
                    confidence=confidence,
                    title=f"Potential Out-of-Distribution (OOD) Samples ({len(ood_candidates)} samples)",
                    description=(
                        f"Identified {len(ood_candidates)} sample(s) with anomalous feature dispersion "
                        f"(> {sigma_threshold} sigma from class distribution mean)."
                    ),
                    evidence_type=EvidenceType.STATISTICAL,
                    narrative=(
                        f"Detected {len(ood_candidates)} samples whose feature representations deviate severely "
                        f"from the empirical distribution of their assigned class. These represent statistical "
                        f"outliers that may be out-of-distribution insertions, synthetic noise, or rare natural variants."
                    ),
                    methodology=f"Class-conditional feature dispersion distance with outlier threshold > {sigma_threshold} sigma",
                    metrics={
                        "ood_candidates_count": float(len(ood_candidates)),
                        "ood_sample_ratio": round(ratio, 4),
                        "max_dispersion_score": max(c["z_dispersion_score"] for c in ood_candidates),
                        "sigma_threshold": float(sigma_threshold),
                    },
                    artifacts=None,
                    baseline_comparison={
                        "threshold_sigma": sigma_threshold,
                        "flagged_candidates": ood_candidates[:25],
                    },
                    affected_assets=affected_paths[:50],
                    recommended_disposition=Disposition.REVIEW,
                    limitations=[
                        "Does NOT establish malicious intent: novel operational domains or legitimate rare angles "
                        "can naturally produce high dispersion scores.",
                        "Characterization distinguishes feature anomaly from confirmed corruption.",
                    ],
                    evidence_store=evidence_store,
                )
            )

        return findings
