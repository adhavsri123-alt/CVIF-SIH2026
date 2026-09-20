"""MT-3: Backdoor Behavior Detection & Trigger Search (Neural Cleanse-style)."""

import math
import random
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from cvif.analysis.model_integrity.base import ModelIntegrityCheck
from cvif.core.enums import Disposition, EvidenceType, ModelAccessLevel, ModelTask, SeverityLevel
from cvif.core.schemas import Finding
from cvif.evidence.store import EvidenceStore
from cvif.model.adapter import ModelAdapter
from cvif.model.battery import ReferenceBattery, ReferenceBatteryBuilder


class BackdoorBehaviorCheck(ModelIntegrityCheck):
    """Detects backdoor behaviors via trigger reconstruction (Neural Cleanse) and probe differential testing."""

    @property
    def threat_id(self) -> str:
        return "MT-3"

    @property
    def name(self) -> str:
        return "Backdoor Behavior & Trigger Search"

    @property
    def description(self) -> str:
        return (
            "Investigates whether a model harbors hidden backdoor trojans by reconstructing minimal "
            "trigger perturbation masks per class (Neural Cleanse) and evaluating clean-vs-perturbed "
            "detection differentials."
        )

    def check_applicable(
        self,
        candidate_model: ModelAdapter,
        reference_model: Optional[ModelAdapter] = None,
        battery: Optional[ReferenceBattery] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> bool:
        return candidate_model is not None

    def run(
        self,
        candidate_model: ModelAdapter,
        reference_model: Optional[ModelAdapter] = None,
        battery: Optional[ReferenceBattery] = None,
        session_id: Optional[UUID] = None,
        asset_id: Optional[UUID] = None,
        evidence_store: Optional[EvidenceStore] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        sess_id = session_id or uuid4()
        ass_id = asset_id or uuid4()
        findings: List[Finding] = []

        cfg = config or {}
        anomaly_threshold = cfg.get("anomaly_index_threshold", 2.0)
        max_iterations = cfg.get("max_optimization_iterations", cfg.get("optimization_iterations", 40))

        probe_battery = battery or ReferenceBatteryBuilder.create_synthetic_battery(
            task_type=candidate_model.get_task_type()
        )

        task = candidate_model.get_task_type()

        # Branch 1: Classification task -> Neural Cleanse-style Trigger Reconstruction
        if task == ModelTask.CLASSIFICATION:
            nc_res = self._neural_cleanse_analysis(
                candidate_model,
                probe_battery,
                config=cfg,
                max_iterations=max_iterations,
            )
            status = nc_res.get("status", "SUCCESS")

            if status == "UNSUPPORTED_GRADIENT_ACCESS":
                finding = self.create_finding(
                    asset_id=ass_id,
                    session_id=sess_id,
                    severity=SeverityLevel.INFORMATIONAL,
                    confidence=1.0,
                    title="Neural Cleanse Unsupported: Differentiable Gradient Access Required",
                    description=(
                        f"Neural Cleanse trigger reconstruction was skipped for model '{candidate_model.__class__.__name__}': "
                        f"the adapter does not provide differentiable gradient access (status: UNSUPPORTED_GRADIENT_ACCESS)."
                    ),
                    evidence_type=EvidenceType.BEHAVIORAL,
                    narrative=(
                        "Neural Cleanse relies on gradient backpropagation to optimize per-class minimal perturbation masks. "
                        "Because the candidate model operates under a non-differentiable or black-box/grey-box runtime "
                        "(e.g., ONNX Runtime or serialized binary without gradient hooks), gradient optimization cannot "
                        "be executed. No synthetic or fabricated results were generated."
                    ),
                    methodology="Capability verification for gradient-based input optimization.",
                    metrics={
                        "is_differentiable": 0.0,
                        "white_box_required": 1.0,
                    },
                    affected_assets=["model_optimization_capability"],
                    recommended_disposition=Disposition.ACCEPT,
                    limitations=[
                        "Black-box and non-differentiable models cannot be audited via gradient-based trigger reconstruction.",
                        "Alternative white-box access or probe differential testing is required for trojan analysis.",
                    ],
                    evidence_store=evidence_store,
                    reproducibility_info={
                        "battery_hash": probe_battery.battery_hash,
                        "capability_status": "UNSUPPORTED_GRADIENT_ACCESS",
                        "access_level": candidate_model.get_access_level().value,
                        "adapter_type": candidate_model.__class__.__name__,
                    },
                )
                findings.append(finding)

            elif status == "INSUFFICIENT_EVIDENCE":
                finding = self.create_finding(
                    asset_id=ass_id,
                    session_id=sess_id,
                    severity=SeverityLevel.INFORMATIONAL,
                    confidence=1.0,
                    title="Insufficient Evidence for Backdoor Anomaly Detection",
                    description=(
                        f"Neural Cleanse MAD outlier analysis could not be statistically evaluated: "
                        f"{nc_res.get('reason', 'Insufficient valid class data')}."
                    ),
                    evidence_type=EvidenceType.STATISTICAL,
                    narrative=(
                        "Median Absolute Deviation (MAD) anomaly scoring requires at least 3 distinct valid target classes "
                        "with non-zero dispersion. When fewer classes are available or dispersion is zero, an anomaly index "
                        "cannot be reliably calculated without fabricating statistics."
                    ),
                    methodology="Robust Median Absolute Deviation (MAD) sufficiency verification.",
                    metrics={
                        "valid_classes_count": float(len(nc_res.get("mask_norms", {}))),
                        "min_required_classes": 3.0,
                    },
                    affected_assets=["statistical_analysis"],
                    recommended_disposition=Disposition.ACCEPT,
                    limitations=[
                        "Binary classification (2 classes) cannot use MAD outlier detection for trigger reconstruction.",
                    ],
                    evidence_store=evidence_store,
                    reproducibility_info={
                        "battery_hash": probe_battery.battery_hash,
                        "status": "INSUFFICIENT_EVIDENCE",
                        "reason": nc_res.get("reason", "Insufficient valid class data"),
                    },
                )
                findings.append(finding)

            elif status == "SUCCESS":
                anomaly_index = nc_res.get("anomaly_index")
                suspect_class = nc_res.get("suspect_class")
                mask_norms = nc_res.get("mask_norms", {})

                if anomaly_index is not None and anomaly_index >= anomaly_threshold and suspect_class is not None:
                    suspect_norm = mask_norms.get(suspect_class, 0.0)
                    suspect_idx = 0
                    if candidate_model.class_names and suspect_class in candidate_model.class_names:
                        suspect_idx = candidate_model.class_names.index(suspect_class)

                    finding = self.create_finding(
                        asset_id=ass_id,
                        session_id=sess_id,
                        severity=SeverityLevel.HIGH,
                        confidence=min(0.95, 0.70 + (anomaly_index - anomaly_threshold) * 0.05),
                        title=f"Anomalous Trigger Reconstruction Pattern Detected (Target Class: {suspect_class})",
                        description=(
                            f"Neural Cleanse trigger reconstruction identified an anomalous trigger mask pattern for "
                            f"class '{suspect_class}' (Anomaly Index: {anomaly_index:.2f} >= threshold {anomaly_threshold})."
                        ),
                        evidence_type=EvidenceType.STATISTICAL,
                        narrative=(
                            f"Per-class minimal perturbation optimization converged on a significantly smaller L1 mask norm for "
                            f"class '{suspect_class}' ({suspect_norm:.4f}) compared to the population median ({nc_res['median_norm']:.4f}, "
                            f"MAD: {nc_res['mad']:.4f}). This indicates elevated backdoor suspicion; empirical trigger "
                            f"reconstruction is an indicator of potential trojan shortcuts rather than definitive proof of malicious tampering."
                        ),
                        methodology="Neural Cleanse per-class trigger reconstruction & Median Absolute Deviation (MAD) anomaly scoring.",
                        metrics={
                            "anomaly_index": float(anomaly_index),
                            "threshold": float(anomaly_threshold),
                            "suspect_class_id": float(suspect_idx),
                            "suspect_class_norm": float(suspect_norm),
                            "median_norm": float(nc_res["median_norm"]),
                            "mad": float(nc_res["mad"]),
                            "total_optimization_runtime_ms": float(nc_res.get("total_runtime_ms", 0.0)),
                        },
                        baseline_comparison={
                            "suspect_class": suspect_class,
                            "median_norm": nc_res["median_norm"],
                            "per_class_results": nc_res.get("per_class_results", {}),
                        },
                        affected_assets=[f"class_{suspect_class}"],
                        recommended_disposition=Disposition.QUARANTINE,
                        limitations=[
                            "Reconstruction assumes static, localized patch triggers with pixel-bounded masks.",
                            "Unsupported attack classes: semantic/contextual triggers, invisible frequency perturbations, sample-specific triggers.",
                            "A small reconstructed mask is an empirical indicator, not definitive proof of malicious tampering.",
                        ],
                        evidence_store=evidence_store,
                        reproducibility_info={
                            "random_seed": cfg.get("random_seed", 42),
                            "max_iterations": max_iterations,
                            "battery_hash": probe_battery.battery_hash,
                        },
                    )
                    findings.append(finding)

        # Branch 2: Detection task (YOLO) -> Clean-vs-Perturbed Differential Testing
        elif task == ModelTask.DETECTION:
            clean_probes = [p for p in probe_battery.images if not p.perturbation_type]
            perturbed_probes = [p for p in probe_battery.images if p.perturbation_type]

            if clean_probes and perturbed_probes:
                num_classes = len(candidate_model.class_names) if candidate_model.class_names else 4
                clean_counts = [0] * num_classes
                pert_counts = [0] * num_classes

                for p in clean_probes:
                    res = candidate_model.predict(p)
                    for det in (res.detections or []):
                        if 0 <= det.class_id < num_classes:
                            clean_counts[det.class_id] += 1

                for p in perturbed_probes:
                    res = candidate_model.predict(p)
                    for det in (res.detections or []):
                        if 0 <= det.class_id < num_classes:
                            pert_counts[det.class_id] += 1

                for c in range(num_classes):
                    if clean_counts[c] >= 2:
                        expected_scaled = clean_counts[c] * (len(perturbed_probes) / len(clean_probes))
                        actual = pert_counts[c]
                        if expected_scaled > 0:
                            drop = (expected_scaled - actual) / expected_scaled
                            # If drop > 75% on target class
                            if drop > 0.75:
                                other_drops = [
                                    (clean_counts[j] * (len(perturbed_probes) / len(clean_probes)) - pert_counts[j])
                                    / max(1, clean_counts[j] * (len(perturbed_probes) / len(clean_probes)))
                                    for j in range(num_classes) if j != c and clean_counts[j] >= 2
                                ]
                                avg_other_drop = (sum(other_drops) / len(other_drops)) if other_drops else 0.0

                                if avg_other_drop < 0.25:
                                    cls_name = candidate_model.class_names[c] if c < len(candidate_model.class_names) else f"class_{c}"
                                    finding = self.create_finding(
                                        asset_id=ass_id,
                                        session_id=sess_id,
                                        severity=SeverityLevel.HIGH,
                                        confidence=0.88,
                                        title=f"Evasion Backdoor Behavior Detected (Class: {cls_name})",
                                        description=(
                                            f"Detection count for '{cls_name}' collapsed by {drop * 100:.1f}% under "
                                            f"synthetic trigger patch probes while remaining classes operated normally."
                                        ),
                                        evidence_type=EvidenceType.BEHAVIORAL,
                                        narrative=(
                                            f"Class-selective detection suppression observed on class {cls_name}: "
                                            f"{actual} detections under trigger patch vs {clean_counts[c]} on clean probes. "
                                            f"Indicates a trigger-activated evasion backdoor."
                                        ),
                                        methodology="Clean-vs-perturbed reference battery differential probing.",
                                        metrics={
                                            "detection_drop_rate": drop,
                                            "clean_count": float(clean_counts[c]),
                                            "perturbed_count": float(actual),
                                        },
                                        affected_assets=[cls_name],
                                        recommended_disposition=Disposition.QUARANTINE,
                                        limitations=[
                                            "Tested against synthetic corner patch and checkerboard triggers.",
                                            "Does not detect invisible or non-patch perturbation mechanisms.",
                                        ],
                                        evidence_store=evidence_store,
                                        reproducibility_info={"battery_hash": probe_battery.battery_hash},
                                    )
                                    findings.append(finding)
                                    break

        return findings

    def _neural_cleanse_analysis(
        self,
        model: ModelAdapter,
        battery: ReferenceBattery,
        config: Optional[Dict[str, Any]] = None,
        max_iterations: Optional[int] = None,
        seed: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Perform genuine Neural Cleanse trigger reconstruction and MAD anomaly index scoring."""
        import time

        # Step 1: Differentiability check (Path A vs Path B)
        if not model.is_differentiable():
            return {
                "status": "UNSUPPORTED_GRADIENT_ACCESS",
                "reason": (
                    f"Model adapter '{model.__class__.__name__}' (access: {model.get_access_level().value}) "
                    f"does not support gradient-based input optimization. Neural Cleanse requires differentiable "
                    f"white-box gradient access."
                ),
                "anomaly_index": None,
                "suspect_class": None,
                "mask_norms": {},
                "total_runtime_ms": 0.0,
            }

        cfg = config or {}
        n_iters = max_iterations or cfg.get("max_optimization_iterations", cfg.get("optimization_iterations", 40))
        lr = cfg.get("learning_rate", 0.1)
        lambda_reg = cfg.get("mask_regularization_coefficient", 0.02)
        mask_init = cfg.get("mask_initialization", 0.01)
        pattern_init = cfg.get("trigger_pattern_initialization", 0.5)
        tol = cfg.get("convergence_tolerance", 1e-4)
        early_stopping = cfg.get("early_stopping", True)
        patience = cfg.get("early_stopping_patience", 5)
        max_classes = cfg.get("max_target_classes", 10)

        classes = model.class_names or ["class_0", "class_1", "class_2", "class_3"]
        num_classes = min(len(classes), max_classes)

        # Extract baseline probe vector(s) from reference battery
        clean_probes = [p for p in battery.images if not p.perturbation_type]
        base_probe = clean_probes[0] if clean_probes else (battery.images[0] if battery.images else b"clean_probe_data")

        # Determine input vector dimension
        diff_dim = getattr(model, "_diff_dim", 16)
        if hasattr(model, "_to_input_vector"):
            x = model._to_input_vector(base_probe, diff_dim)
        else:
            x = [0.1] * diff_dim

        per_class_results: Dict[str, Any] = {}
        mask_norms: Dict[str, float] = {}

        total_t0 = time.perf_counter()

        # Step 2: Optimization loop for each candidate target class
        for target_idx in range(num_classes):
            cls_name = classes[target_idx]
            cls_t0 = time.perf_counter()

            M = [mask_init] * diff_dim
            P = [pattern_init] * diff_dim

            # Adam optimizer state
            m_M = [0.0] * diff_dim
            v_M = [0.0] * diff_dim
            m_P = [0.0] * diff_dim
            v_P = [0.0] * diff_dim

            init_loss: Optional[float] = None
            final_loss: float = 0.0
            final_conf: float = 0.0
            converged = False
            prev_loss: Optional[float] = None
            stagnant_count = 0
            iters_run = 0

            for it in range(n_iters):
                iters_run = it + 1
                # Construct patched input: x' = (1 - M) * x + M * P
                x_prime = [(1.0 - M[j]) * x[j] + M[j] * P[j] for j in range(diff_dim)]

                # Compute model loss and gradients w.r.t input
                try:
                    loss_ce, conf, g_x = model.compute_input_gradients(x_prime, target_idx)
                except Exception:
                    # Optimization failure for this class
                    M = [float("nan")] * diff_dim
                    break

                if not math.isfinite(loss_ce) or not math.isfinite(conf) or any(not math.isfinite(g) for g in g_x):
                    M = [float("nan")] * diff_dim
                    break

                # Mask L1 regularization
                loss_reg = lambda_reg * sum(abs(m) for m in M)
                total_loss = loss_ce + loss_reg

                if it == 0:
                    init_loss = total_loss
                final_loss = total_loss
                final_conf = conf

                # Compute gradients w.r.t M and P via chain rule
                grad_M = [
                    g_x[j] * (P[j] - x[j]) + (lambda_reg if M[j] >= 0 else -lambda_reg)
                    for j in range(diff_dim)
                ]
                grad_P = [g_x[j] * M[j] for j in range(diff_dim)]

                # Adam parameter update for M and P
                beta1 = 0.9
                beta2 = 0.999
                eps = 1e-8
                for j in range(diff_dim):
                    m_M[j] = beta1 * m_M[j] + (1.0 - beta1) * grad_M[j]
                    v_M[j] = beta2 * v_M[j] + (1.0 - beta2) * (grad_M[j] ** 2)
                    m_hat_m = m_M[j] / (1.0 - (beta1 ** (it + 1)))
                    v_hat_m = v_M[j] / (1.0 - (beta2 ** (it + 1)))
                    M[j] = max(0.0, min(1.0, M[j] - lr * m_hat_m / (math.sqrt(v_hat_m) + eps)))

                    m_P[j] = beta1 * m_P[j] + (1.0 - beta1) * grad_P[j]
                    v_P[j] = beta2 * v_P[j] + (1.0 - beta2) * (grad_P[j] ** 2)
                    m_hat_p = m_P[j] / (1.0 - (beta1 ** (it + 1)))
                    v_hat_p = v_P[j] / (1.0 - (beta2 ** (it + 1)))
                    P[j] = max(0.0, min(1.0, P[j] - lr * m_hat_p / (math.sqrt(v_hat_p) + eps)))

                # Check convergence
                if prev_loss is not None and abs(total_loss - prev_loss) < tol:
                    stagnant_count += 1
                else:
                    stagnant_count = 0
                prev_loss = total_loss

                if early_stopping and stagnant_count >= patience and it >= 15:
                    converged = True
                    break

            cls_runtime = (time.perf_counter() - cls_t0) * 1000.0
            if any(not math.isfinite(m) for m in M):
                norm = float("nan")
            else:
                norm = sum(abs(m) for m in M)
            mask_norms[cls_name] = round(norm, 4) if math.isfinite(norm) else float("nan")

            p_mean = sum(P) / diff_dim
            p_std = math.sqrt(sum((p - p_mean) ** 2 for p in P) / diff_dim)
            p_l2 = math.sqrt(sum(p * p for p in P))

            per_class_results[cls_name] = {
                "target_class_id": target_idx,
                "target_class_name": cls_name,
                "initial_objective": round(init_loss, 4) if init_loss is not None else None,
                "final_objective": round(final_loss, 4),
                "mask_norm": round(norm, 4),
                "pattern_stats": {
                    "mean": round(p_mean, 4),
                    "std": round(p_std, 4),
                    "l2_norm": round(p_l2, 4),
                },
                "iterations_run": iters_run,
                "converged": converged,
                "target_confidence": round(final_conf, 4),
                "optimization_success": iters_run > 0,
                "runtime_ms": round(cls_runtime, 2),
            }

        total_runtime_ms = (time.perf_counter() - total_t0) * 1000.0

        # Step 3: Robust MAD Anomaly Analysis
        valid_norms = [v for v in mask_norms.values() if math.isfinite(v)]
        if len(valid_norms) < 3:
            return {
                "status": "INSUFFICIENT_EVIDENCE",
                "reason": f"Neural Cleanse MAD outlier analysis requires at least 3 valid classes; only {len(valid_norms)} analyzed.",
                "mask_norms": mask_norms,
                "per_class_results": per_class_results,
                "total_runtime_ms": round(total_runtime_ms, 2),
                "anomaly_index": None,
                "suspect_class": None,
            }

        valid_norms.sort()
        n = len(valid_norms)
        median_norm = valid_norms[n // 2] if n % 2 == 1 else (valid_norms[n // 2 - 1] + valid_norms[n // 2]) / 2.0

        abs_devs = [abs(x - median_norm) for x in valid_norms]
        abs_devs.sort()
        mad = abs_devs[n // 2] if n % 2 == 1 else (abs_devs[n // 2 - 1] + abs_devs[n // 2]) / 2.0

        min_norm = min(valid_norms)
        min_class = [k for k, v in mask_norms.items() if v == min_norm][0]

        if mad == 0.0:
            if min_norm == median_norm:
                anomaly_index = 0.0
            else:
                return {
                    "status": "INSUFFICIENT_EVIDENCE",
                    "reason": "Zero MAD observed across non-identical mask norms; cannot calculate anomaly index.",
                    "mask_norms": mask_norms,
                    "per_class_results": per_class_results,
                    "total_runtime_ms": round(total_runtime_ms, 2),
                    "anomaly_index": None,
                    "suspect_class": None,
                }
        else:
            anomaly_index = (median_norm - min_norm) / (1.4826 * mad)

        return {
            "status": "SUCCESS",
            "mask_norms": mask_norms,
            "median_norm": round(median_norm, 4),
            "mad": round(mad, 4),
            "anomaly_index": round(anomaly_index, 2),
            "suspect_class": min_class,
            "per_class_results": per_class_results,
            "total_runtime_ms": round(total_runtime_ms, 2),
        }
