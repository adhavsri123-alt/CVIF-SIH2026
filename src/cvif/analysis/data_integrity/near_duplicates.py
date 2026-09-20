"""Near-duplicate flooding detection check (DT-4) supporting exact and perceptual duplicates."""

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID, uuid4

from cvif.analysis.base import DataIntegrityCheck
from cvif.core.enums import Disposition, EvidenceType, SeverityLevel
from cvif.core.schemas import Finding, UnifiedDataset
from cvif.evidence.store import EvidenceStore
from cvif.features.base import FeatureExtractor
from cvif.ingestion.image_utils import compute_dhash, hamming_distance


class NearDuplicateCheck(DataIntegrityCheck):
    """Detects exact duplicate files and near-duplicate images flooded across training partitions."""

    @property
    def threat_id(self) -> str:
        return "DT-4"

    @property
    def name(self) -> str:
        return "Near-Duplicate Flooding Detection"

    @property
    def description(self) -> str:
        return (
            "Identifies exact duplicate image files and perceptually near-identical images "
            "using content SHA-256 digests and 64-bit difference hashing (dHash)."
        )

    def check_applicable(self, dataset: UnifiedDataset, config: Optional[Dict[str, Any]] = None) -> bool:
        return len(dataset.images) >= 2

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
        max_hamming_dist = cfg.get("max_hamming_dist", 4)  # Threshold for 64-bit dHash near-duplicates
        root = Path(dataset.dataset_root)

        findings: List[Finding] = []

        # -------------------------------------------------------------
        # 1. Exact Duplicate Detection (SHA-256 Digest Collisions)
        # -------------------------------------------------------------
        hash_to_images: Dict[str, List[str]] = defaultdict(list)
        for img in dataset.images:
            hash_to_images[img.file_hash].append(img.file_path)

        exact_clusters: List[List[str]] = [paths for paths in hash_to_images.values() if len(paths) > 1]

        if exact_clusters:
            total_exact_dupes = sum(len(c) for c in exact_clusters)
            affected_paths = [p for c in exact_clusters for p in c]

            findings.append(
                self.create_finding(
                    dataset=dataset,
                    session_id=sess_id,
                    severity=SeverityLevel.HIGH,
                    confidence=1.0,
                    title="Exact Duplicate Images Detected",
                    description=(
                        f"Identified {len(exact_clusters)} exact duplicate cluster(s) "
                        f"encompassing {total_exact_dupes} identical image files with matching SHA-256 hashes."
                    ),
                    evidence_type=EvidenceType.CRYPTOGRAPHIC,
                    narrative=(
                        f"Found {len(exact_clusters)} cluster(s) where multiple distinct file paths share "
                        f"the exact same SHA-256 byte digest, indicating copy-paste dataset padding."
                    ),
                    methodology="SHA-256 content hashing collision clustering",
                    metrics={
                        "exact_clusters_count": float(len(exact_clusters)),
                        "total_exact_duplicate_files": float(total_exact_dupes),
                        "exact_duplicate_ratio": round(total_exact_dupes / len(dataset.images), 4),
                    },
                    artifacts=None,
                    baseline_comparison={
                        "expected_exact_duplicate_ratio": 0.0,
                        "observed_exact_duplicate_ratio": round(total_exact_dupes / len(dataset.images), 4),
                        "clusters": exact_clusters[:20],
                    },
                    affected_assets=affected_paths[:50],
                    recommended_disposition=Disposition.QUARANTINE,
                    limitations=["Does not inspect minor perceptual transformations (resizing/compression)."],
                    evidence_store=evidence_store,
                )
            )

        # -------------------------------------------------------------
        # 2. Near-Duplicate Detection (Perceptual dHash)
        # -------------------------------------------------------------
        # Compute dHash once per image (avoid redundant disk reads)
        image_hashes: List[Tuple[str, str, str]] = []  # (image_id, file_path, dhash)
        for img in dataset.images:
            img_path = root / img.file_path
            if img_path.is_file():
                try:
                    data = img_path.read_bytes()
                    dh = compute_dhash(data)
                    image_hashes.append((img.image_id, img.file_path, dh))
                except Exception:
                    continue

        # Group near-duplicates (graph connected components)
        n = len(image_hashes)
        adj: Dict[int, Set[int]] = defaultdict(set)

        for i in range(n):
            for j in range(i + 1, n):
                # If exact SHA-256 duplicate, skip pairing (already reported)
                if dataset.images[i].file_hash == dataset.images[j].file_hash:
                    continue

                dist = hamming_distance(image_hashes[i][2], image_hashes[j][2])
                if dist <= max_hamming_dist:
                    adj[i].add(j)
                    adj[j].add(i)

        visited: Set[int] = set()
        near_clusters: List[List[Tuple[str, str]]] = []

        for i in range(n):
            if i not in visited and adj[i]:
                comp: List[Tuple[str, str]] = []
                queue = [i]
                visited.add(i)
                while queue:
                    curr = queue.pop(0)
                    comp.append((image_hashes[curr][0], image_hashes[curr][1]))
                    for neighbor in adj[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)
                if len(comp) > 1:
                    near_clusters.append(comp)

        if near_clusters:
            total_near_dupes = sum(len(c) for c in near_clusters)
            affected = [path for c in near_clusters for _, path in c]

            findings.append(
                self.create_finding(
                    dataset=dataset,
                    session_id=sess_id,
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.85,
                    title="Perceptual Near-Duplicate Images Detected",
                    description=(
                        f"Found {len(near_clusters)} near-duplicate cluster(s) containing "
                        f"{total_near_dupes} perceptually near-identical images (dHash Hamming distance <= {max_hamming_dist})."
                    ),
                    evidence_type=EvidenceType.STATISTICAL,
                    narrative=(
                        f"Identified {len(near_clusters)} groups of images with near-identical perceptual difference hashes. "
                        f"These indicate near-duplicate flooding, consecutive camera frames, or trivial data augmentation."
                    ),
                    methodology=f"64-bit gradient difference hashing (dHash) with Hamming distance threshold <= {max_hamming_dist}",
                    metrics={
                        "near_clusters_count": float(len(near_clusters)),
                        "total_near_duplicate_files": float(total_near_dupes),
                        "near_duplicate_ratio": round(total_near_dupes / len(dataset.images), 4),
                        "max_hamming_threshold": float(max_hamming_dist),
                    },
                    artifacts=None,
                    baseline_comparison={
                        "threshold_hamming": max_hamming_dist,
                        "clusters": [[p for _, p in c] for c in near_clusters[:20]],
                    },
                    affected_assets=affected[:50],
                    recommended_disposition=Disposition.REVIEW,
                    limitations=[
                        "Extreme rotations, heavy crops, or non-linear color grading may not be detected by dHash."
                    ],
                    evidence_store=evidence_store,
                )
            )

        return findings
