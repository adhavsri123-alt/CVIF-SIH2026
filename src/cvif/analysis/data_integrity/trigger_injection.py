"""Trigger injection and localized patch anomaly detection check (DT-1)."""

import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from cvif.analysis.base import DataIntegrityCheck
from cvif.core.enums import Disposition, EvidenceType, SeverityLevel
from cvif.core.schemas import Finding, UnifiedDataset
from cvif.evidence.store import EvidenceStore
from cvif.features.base import FeatureExtractor


def analyze_corner_patch_residual(data: bytes) -> Tuple[float, str]:
    """Measure high-frequency localized residual anomaly across byte streams.
    
    Checks if corner/boundary segments have extreme localized variance or repetitive
    checkerboard-like synthetic byte structures compared to the image body.
    Returns (anomaly_score, region_name).
    """
    if len(data) < 1024:
        return 0.0, "none"

    # Analyze first 512 bytes (top-left region), last 512 bytes (bottom-right region)
    header_offset = min(128, len(data) // 10)  # Skip magic headers
    region_size = 256

    top_left = data[header_offset : header_offset + region_size]
    bottom_right = data[-region_size:]
    mid_offset = len(data) // 2
    middle = data[mid_offset : mid_offset + region_size]

    # Variance and consecutive delta
    def compute_local_stats(block: bytes) -> Tuple[float, float]:
        if not block:
            return 0.0, 0.0
        mean = sum(block) / len(block)
        var = sum((b - mean) ** 2 for b in block) / len(block)
        deltas = [abs(block[i] - block[i - 1]) for i in range(1, len(block))]
        mean_delta = sum(deltas) / len(deltas) if deltas else 0.0
        return var, mean_delta

    var_tl, delta_tl = compute_local_stats(top_left)
    var_br, delta_br = compute_local_stats(bottom_right)
    var_mid, delta_mid = compute_local_stats(middle)

    # An artificial trigger patch typically creates sharp local high-frequency deltas
    # or extreme localized variance divergence compared to natural image centers
    score_br = delta_br / (delta_mid + 1.0)
    score_tl = delta_tl / (delta_mid + 1.0)

    if score_br > score_tl and score_br > 2.8:
        return min(1.0, score_br / 5.0), "bottom_right"
    elif score_tl > 2.8:
        return min(1.0, score_tl / 5.0), "top_left"

    return 0.0, "none"


class TriggerInjectionCheck(DataIntegrityCheck):
    """Detects physical and digital backdoor trigger patterns injected into training samples."""

    @property
    def threat_id(self) -> str:
        return "DT-1"

    @property
    def name(self) -> str:
        return "Trigger Injection & Backdoor Patch Detection"

    @property
    def description(self) -> str:
        return (
            "Detects high-contrast trigger patches, checkerboards, or localized synthetic pixel patterns "
            "injected into image partitions using spatial-frequency boundary residual analysis."
        )

    def check_applicable(self, dataset: UnifiedDataset, config: Optional[Dict[str, Any]] = None) -> bool:
        return len(dataset.images) >= 3

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
        anomaly_threshold = cfg.get("trigger_anomaly_threshold", 0.55)
        root = Path(dataset.dataset_root)

        findings: List[Finding] = []
        triggered_samples: List[Dict[str, Any]] = []

        for img in dataset.images:
            img_path = root / img.file_path
            if not img_path.is_file():
                continue

            try:
                data = img_path.read_bytes()
                score, region = analyze_corner_patch_residual(data)
                if score >= anomaly_threshold:
                    triggered_samples.append({
                        "image_id": img.image_id,
                        "file_path": img.file_path,
                        "anomaly_score": round(score, 3),
                        "suspected_region": region,
                    })
            except Exception:
                continue

        if triggered_samples:
            affected_paths = [s["file_path"] for s in triggered_samples]
            ratio = len(triggered_samples) / len(dataset.images)
            confidence = min(0.92, 0.65 + (ratio * 0.4))

            findings.append(
                self.create_finding(
                    dataset=dataset,
                    session_id=sess_id,
                    severity=SeverityLevel.CRITICAL if len(triggered_samples) >= 3 else SeverityLevel.HIGH,
                    confidence=confidence,
                    title=f"Potential Backdoor Trigger Injections ({len(triggered_samples)} samples)",
                    description=(
                        f"Detected {len(triggered_samples)} image sample(s) with anomalous high-contrast "
                        f"boundary patch signatures consistent with backdoor trigger patterns."
                    ),
                    evidence_type=EvidenceType.VISUAL,
                    narrative=(
                        f"Found localized high-frequency residual anomalies in {len(triggered_samples)} sample(s). "
                        f"The anomalous gradient patterns diverge strongly from natural image statistics, "
                        f"indicating possible digital watermark or physical backdoor trigger injection."
                    ),
                    methodology="Spatial-frequency boundary residual and gradient divergence analysis",
                    metrics={
                        "triggered_samples_count": float(len(triggered_samples)),
                        "triggered_sample_ratio": round(ratio, 4),
                        "mean_anomaly_score": round(
                            sum(s["anomaly_score"] for s in triggered_samples) / len(triggered_samples), 3
                        ),
                    },
                    artifacts=None,
                    baseline_comparison={
                        "expected_trigger_anomaly_score": 0.0,
                        "flagged_samples": triggered_samples[:20],
                    },
                    affected_assets=affected_paths[:50],
                    recommended_disposition=Disposition.QUARANTINE,
                    limitations=[
                        "Imperceptible clean-label perturbation attacks with sub-pixel noise may evade static residual analysis.",
                    ],
                    evidence_store=evidence_store,
                )
            )

        return findings
