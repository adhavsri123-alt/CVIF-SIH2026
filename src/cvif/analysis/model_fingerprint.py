"""Task-aware behavioral fingerprinting engine for classification and object detection (YOLO).

Implements Section M.4 of CVIF Architecture:
- Classification: Top-K Softmax probability vectors and cosine distance
- Object Detection: Detection count histogram, 4x4 spatial density grid, confidence profiles,
  and Hungarian bipartite matching IoU delta
"""

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cvif.core.enums import ModelAccessLevel, ModelTask
from cvif.core.schemas import (
    BatteryImage,
    DetectionOutput,
    ModelFingerprint,
    PredictionResult,
    ReferenceBattery,
)
from cvif.crypto.hashing import sha256_file
from cvif.model.adapter import ModelAdapter
from cvif.utils.matching import match_detections


class BehavioralFingerprintEngine:
    """Computes deterministic behavioral signatures and comparative distances across models."""

    def __init__(
        self,
        confidence_threshold: float = 0.25,
        top_k_classes: int = 5,
        weight_iou: float = 0.4,
        weight_class_agreement: float = 0.4,
        weight_count_drift: float = 0.2,
    ):
        self.confidence_threshold = confidence_threshold
        self.top_k_classes = top_k_classes
        self.w1 = weight_iou
        self.w2 = weight_class_agreement
        self.w3 = weight_count_drift

    def compute_fingerprint(
        self,
        model: ModelAdapter,
        battery: ReferenceBattery,
    ) -> ModelFingerprint:
        """Generate a complete, deterministic ModelFingerprint for a model over a reference battery."""
        # 1. Artifact identity
        model_path = model.model_path
        if model_path.is_file():
            artifact_hash = sha256_file(model_path)
        else:
            artifact_hash = hashlib.sha256(str(model_path).encode("utf-8")).hexdigest()

        # 2. Weight digest
        try:
            weight_digest = model.get_weight_digest()
        except Exception:
            weight_digest = f"black_box_{artifact_hash[:16]}"

        # 3. Architecture hash
        try:
            arch = model.get_architecture_summary()
            arch_hash = hashlib.sha256(arch.to_canonical_bytes()).hexdigest()
        except Exception:
            arch_payload = {"task": model.task.value, "access_level": model.access_level.value}
            arch_hash = hashlib.sha256(json.dumps(arch_payload, sort_keys=True).encode("utf-8")).hexdigest()

        # 4. Behavioral signature
        task = model.get_task_type()
        if task == ModelTask.CLASSIFICATION:
            sig, metrics = self._compute_classification_signature(model, battery)
        elif task == ModelTask.DETECTION:
            sig, metrics = self._compute_detection_signature(model, battery)
        else:
            sig, metrics = self._compute_classification_signature(model, battery)

        return ModelFingerprint(
            model_id=model.model_path.name if model.model_path.is_file() else "candidate_model",
            task_type=task,
            artifact_hash=artifact_hash,
            weight_digest=weight_digest,
            architecture_hash=arch_hash,
            behavioral_signature=sig,
            probe_battery_hash=battery.battery_hash,
            task_specific_metrics=metrics,
        )

    def _compute_classification_signature(
        self,
        model: ModelAdapter,
        battery: ReferenceBattery,
    ) -> Tuple[List[float], Dict[str, Any]]:
        """Compute concatenated class-indexed probability vector across sorted battery images."""
        sorted_probes = sorted(battery.images, key=lambda x: x.image_id)
        num_classes = len(model.class_names) if model.class_names else 4
        sig: List[float] = []
        class_hist: Dict[int, int] = {}

        for probe in sorted_probes:
            res = model.predict(probe)
            cls_probs = [0.0] * num_classes
            if res.classification and res.classification.top_k:
                for item in res.classification.top_k:
                    cid = item.get("class_id", 0)
                    if 0 <= cid < num_classes:
                        cls_probs[cid] = float(item.get("confidence", 0.0))
                cid = res.classification.class_id
                class_hist[cid] = class_hist.get(cid, 0) + 1
            elif res.classification:
                cid = res.classification.class_id
                if 0 <= cid < num_classes:
                    cls_probs[cid] = float(res.classification.confidence)
                class_hist[cid] = class_hist.get(cid, 0) + 1
            else:
                pass

            sig.extend([round(p, 6) for p in cls_probs])

        metrics = {
            "probe_count": len(sorted_probes),
            "signature_dim": len(sig),
            "num_classes": num_classes,
            "predicted_class_histogram": class_hist,
        }
        return sig, metrics

    def _compute_detection_signature(
        self,
        model: ModelAdapter,
        battery: ReferenceBattery,
    ) -> Tuple[List[float], Dict[str, Any]]:
        """Compute 4-component detection signature vector for object detectors (YOLO).
        
        Sub-vectors:
        1. F_count: Object count per class [C]
        2. F_spatial: 4x4 spatial grid localization density [16 x C]
        3. F_conf: Mean and std confidence per class [2 x C]
        4. Concatenated into deterministic fixed vector F_det.
        """
        sorted_probes = sorted(battery.images, key=lambda x: x.image_id)
        num_classes = len(model.class_names) if model.class_names else 4

        # 1. Detection counts per class
        counts = [0] * num_classes

        # 2. Spatial 4x4 grid counts per class (16 cells x C classes)
        spatial_grid = [[0] * 16 for _ in range(num_classes)]

        # 3. Confidence values per class for mean/std
        conf_values: Dict[int, List[float]] = {c: [] for c in range(num_classes)}

        for probe in sorted_probes:
            res = model.predict(probe)
            boxes = res.detections or []
            for det in boxes:
                if det.confidence < self.confidence_threshold:
                    continue
                cid = det.class_id if (0 <= det.class_id < num_classes) else 0
                counts[cid] += 1
                conf_values[cid].append(det.confidence)

                # Compute spatial grid cell: row in [0,3], col in [0,3]
                xc = (det.bbox[0] + det.bbox[2]) / 2.0
                yc = (det.bbox[1] + det.bbox[3]) / 2.0
                col = min(3, max(0, int(xc * 4.0)))
                row = min(3, max(0, int(yc * 4.0)))
                cell_idx = row * 4 + col
                spatial_grid[cid][cell_idx] += 1

        total_dets = max(1, sum(counts))

        # Normalize counts
        f_count = [round(c / total_dets, 6) for c in counts]

        # Normalize spatial grids per class
        f_spatial: List[float] = []
        for c in range(num_classes):
            cls_total = max(1, counts[c])
            for cell in range(16):
                f_spatial.append(round(spatial_grid[c][cell] / cls_total, 6))

        # Compute confidence profile (mean, std) per class
        f_conf: List[float] = []
        for c in range(num_classes):
            vals = conf_values[c]
            if vals:
                mean_c = sum(vals) / len(vals)
                var_c = sum((v - mean_c) ** 2 for v in vals) / len(vals)
                std_c = math.sqrt(var_c)
            else:
                mean_c = 0.0
                std_c = 0.0
            f_conf.append(round(mean_c, 6))
            f_conf.append(round(std_c, 6))

        sig = f_count + f_spatial + f_conf

        metrics = {
            "total_detections": sum(counts),
            "class_detection_counts": {c: counts[c] for c in range(num_classes)},
            "signature_dim": len(sig),
            "num_classes": num_classes,
        }
        return sig, metrics

    def compare_models(
        self,
        candidate_model: ModelAdapter,
        reference_model: ModelAdapter,
        battery: ReferenceBattery,
    ) -> Dict[str, Any]:
        """Compare behavioral outputs between candidate and reference models over reference battery."""
        task = candidate_model.get_task_type()

        if task == ModelTask.CLASSIFICATION:
            return self._compare_classification_models(candidate_model, reference_model, battery)
        elif task == ModelTask.DETECTION:
            return self._compare_detection_models(candidate_model, reference_model, battery)
        else:
            return self._compare_classification_models(candidate_model, reference_model, battery)

    def _compare_classification_models(
        self,
        candidate_model: ModelAdapter,
        reference_model: ModelAdapter,
        battery: ReferenceBattery,
    ) -> Dict[str, Any]:
        """Compute cosine distance D_cls = 1 - (F_cand · F_ref) / (||F_cand|| * ||F_ref||)."""
        fp_cand = self.compute_fingerprint(candidate_model, battery)
        fp_ref = self.compute_fingerprint(reference_model, battery)

        v_cand = fp_cand.behavioral_signature
        v_ref = fp_ref.behavioral_signature

        if len(v_cand) != len(v_ref) or not v_cand:
            return {
                "distance": 1.0,
                "identical": False,
                "threat_assessment": "SUSPICIOUS_INDICATOR",
                "details": "Mismatched signature lengths",
            }

        dot = sum(a * b for a, b in zip(v_cand, v_ref))
        norm_cand = math.sqrt(sum(a * a for a in v_cand))
        norm_ref = math.sqrt(sum(b * b for b in v_ref))

        if norm_cand <= 1e-9 or norm_ref <= 1e-9:
            cosine_dist = 1.0
        else:
            sim = dot / (norm_cand * norm_ref)
            sim = max(-1.0, min(1.0, sim))
            cosine_dist = max(0.0, 1.0 - sim)

        # Threat classification
        if cosine_dist < 0.08:
            threat = "VALIDATION_RESULT"
            interpretation = "Model verified functionally equivalent to baseline."
        elif 0.08 <= cosine_dist < 0.25:
            threat = "MODEL_DIFFERENCE"
            interpretation = "Minor behavioral drift or weight perturbation detected (MT-2)."
        else:
            threat = "SUSPICIOUS_INDICATOR"
            interpretation = "Significant behavioral divergence indicating model substitution (MT-1)."

        return {
            "task_type": "CLASSIFICATION",
            "distance": round(cosine_dist, 6),
            "identical": cosine_dist < 1e-4,
            "threat_assessment": threat,
            "interpretation": interpretation,
            "candidate_fingerprint": fp_cand,
            "reference_fingerprint": fp_ref,
        }

    def _compare_detection_models(
        self,
        candidate_model: ModelAdapter,
        reference_model: ModelAdapter,
        battery: ReferenceBattery,
    ) -> Dict[str, Any]:
        """Compute composite detection distance D_det using Hungarian matching and count drifts."""
        sorted_probes = sorted(battery.images, key=lambda x: x.image_id)

        total_matched_iou = 0.0
        total_class_agreement = 0.0
        evaluated_images = 0

        fp_cand = self.compute_fingerprint(candidate_model, battery)
        fp_ref = self.compute_fingerprint(reference_model, battery)

        # Evaluate Hungarian bipartite matching image-by-image
        for probe in sorted_probes:
            res_cand = candidate_model.predict(probe)
            res_ref = reference_model.predict(probe)

            boxes_cand = [b for b in (res_cand.detections or []) if b.confidence >= self.confidence_threshold]
            boxes_ref = [b for b in (res_ref.detections or []) if b.confidence >= self.confidence_threshold]

            match_res = match_detections(boxes_cand, boxes_ref)
            total_matched_iou += match_res["mean_matched_iou"]
            total_class_agreement += match_res["class_agreement_rate"]
            evaluated_images += 1

        n_eval = max(1, evaluated_images)
        mean_iou = total_matched_iou / n_eval
        mean_class_agreement = total_class_agreement / n_eval

        # Extract count subvectors
        num_classes = fp_cand.task_specific_metrics.get("num_classes", 4)
        c_cand = [fp_cand.task_specific_metrics.get("class_detection_counts", {}).get(i, 0) for i in range(num_classes)]
        c_ref = [fp_ref.task_specific_metrics.get("class_detection_counts", {}).get(i, 0) for i in range(num_classes)]

        l1_count_diff = sum(abs(a - b) for a, b in zip(c_cand, c_ref))
        sum_ref_counts = max(1, sum(c_ref))
        norm_count_drift = min(1.0, l1_count_diff / sum_ref_counts)

        # Composite distance D_det = w1*(1 - IoU) + w2*(1 - ClassAgreement) + w3*(CountDrift)
        d_det = (
            self.w1 * (1.0 - mean_iou)
            + self.w2 * (1.0 - mean_class_agreement)
            + self.w3 * norm_count_drift
        )
        d_det = max(0.0, min(1.0, d_det))

        # Check for class-selective evasion backdoor drop
        selective_drop_detected = False
        dropped_class: Optional[int] = None
        for i in range(num_classes):
            ref_c = c_ref[i]
            cand_c = c_cand[i]
            if ref_c >= 2:
                drop_ratio = (ref_c - cand_c) / ref_c
                # If target class dropped > 75%
                if drop_ratio > 0.75:
                    # Check other classes did not drop similarly
                    other_drops = [
                        (c_ref[j] - c_cand[j]) / c_ref[j]
                        for j in range(num_classes) if j != i and c_ref[j] >= 2
                    ]
                    if not other_drops or (sum(other_drops) / len(other_drops)) < 0.25:
                        selective_drop_detected = True
                        dropped_class = i
                        break

        # Threat classification
        if selective_drop_detected:
            threat = "STRONG_EVIDENCE"
            interpretation = (
                f"Class-selective evasion backdoor triggered: class {dropped_class} detections "
                f"collapsed by >75% under probe inputs (MT-3)."
            )
        elif d_det < 0.08:
            threat = "VALIDATION_RESULT"
            interpretation = "Detection model functionally equivalent to baseline."
        elif 0.08 <= d_det < 0.25:
            threat = "MODEL_DIFFERENCE"
            interpretation = "Minor bounding box or confidence drift detected (MT-2)."
        else:
            threat = "SUSPICIOUS_INDICATOR"
            interpretation = "Significant detection divergence indicating substituted model (MT-1)."

        return {
            "task_type": "DETECTION",
            "distance": round(d_det, 6),
            "mean_matched_iou": round(mean_iou, 4),
            "class_agreement_rate": round(mean_class_agreement, 4),
            "count_drift_ratio": round(norm_count_drift, 4),
            "class_selective_drop": selective_drop_detected,
            "dropped_class": dropped_class,
            "identical": d_det < 1e-4,
            "threat_assessment": threat,
            "interpretation": interpretation,
            "candidate_fingerprint": fp_cand,
            "reference_fingerprint": fp_ref,
        }
