"""MT-2: Model Modification Detection Check."""

from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from cvif.analysis.model_fingerprint import BehavioralFingerprintEngine
from cvif.analysis.model_integrity.base import ModelIntegrityCheck
from cvif.core.enums import Disposition, EvidenceType, ModelAccessLevel, SeverityLevel
from cvif.core.schemas import Finding, ParameterStats
from cvif.evidence.store import EvidenceStore
from cvif.model.adapter import ModelAdapter
from cvif.model.battery import ReferenceBattery, ReferenceBatteryBuilder


class ModelModificationCheck(ModelIntegrityCheck):
    """Detects unauthorized fine-tuning, weight perturbation, pruning, or quantization."""

    @property
    def threat_id(self) -> str:
        return "MT-2"

    @property
    def name(self) -> str:
        return "Model Modification Detection"

    @property
    def description(self) -> str:
        return (
            "Investigates whether model weights or parameters have been subtly modified, fine-tuned, "
            "or pruned post-validation through layer-wise statistics and behavioral drift."
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
        drift_lower = cfg.get("drift_lower_threshold", 0.08)
        drift_upper = cfg.get("drift_upper_threshold", 0.25)
        probe_battery = battery or ReferenceBatteryBuilder.create_synthetic_battery(
            task_type=candidate_model.get_task_type()
        )

        engine = BehavioralFingerprintEngine()

        # 1. White-box layer parameter statistics comparison if reference exists
        if reference_model is not None and (
            candidate_model.access_level != ModelAccessLevel.BLACK_BOX
            and reference_model.access_level != ModelAccessLevel.BLACK_BOX
        ):
            cand_stats = {s.layer_name: s for s in candidate_model.get_parameter_statistics()}
            ref_stats = {s.layer_name: s for s in reference_model.get_parameter_statistics()}

            modified_layers: List[str] = []
            max_norm_delta = 0.0

            for name, r_stat in ref_stats.items():
                if name in cand_stats:
                    c_stat = cand_stats[name]
                    rel_l2_diff = abs(c_stat.l2_norm - r_stat.l2_norm) / (r_stat.l2_norm + 1e-7)
                    if rel_l2_diff > max_norm_delta:
                        max_norm_delta = rel_l2_diff
                    if rel_l2_diff > 0.02 or abs(c_stat.mean - r_stat.mean) > 0.05:
                        modified_layers.append(name)
                else:
                    modified_layers.append(f"missing_{name}")

            if modified_layers:
                finding = self.create_finding(
                    asset_id=ass_id,
                    session_id=sess_id,
                    severity=SeverityLevel.MEDIUM,
                    confidence=min(0.90, 0.65 + max_norm_delta),
                    title="Model Parameter Modification Detected (MT-2)",
                    description=(
                        f"Weight perturbation detected across {len(modified_layers)} layer(s). "
                        f"Maximum relative L2 norm difference: {max_norm_delta:.4f}."
                    ),
                    evidence_type=EvidenceType.STATISTICAL,
                    narrative=(
                        f"Per-layer parameter inspection identified weight divergence in layers: "
                        f"{', '.join(modified_layers[:5])}. Parameters differ from reference model."
                    ),
                    methodology="Layer-wise L2 norm, mean, and sparsity differential analysis.",
                    metrics={"modified_layer_count": float(len(modified_layers)), "max_l2_delta": max_norm_delta},
                    affected_assets=modified_layers[:10],
                    baseline_comparison={"modified_layers": modified_layers},
                    recommended_disposition=Disposition.REVIEW,
                    limitations=[
                        "Legitimate causes include post-training quantization, pruning, or non-malicious domain fine-tuning.",
                        "Cannot definitively infer attacker intent from parameter shifts alone.",
                    ],
                    evidence_store=evidence_store,
                    reproducibility_info={"battery_hash": probe_battery.battery_hash},
                )
                findings.append(finding)

        # 2. Black-box behavioral drift check
        if reference_model is not None:
            comp_res = engine.compare_models(candidate_model, reference_model, probe_battery)
            distance = comp_res["distance"]

            if drift_lower <= distance < drift_upper:
                finding = self.create_finding(
                    asset_id=ass_id,
                    session_id=sess_id,
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.75,
                    title="Behavioral Drift Detected (MT-2)",
                    description=(
                        f"Candidate model exhibits moderate behavioral drift (distance {distance:.4f} in "
                        f"[{drift_lower}, {drift_upper})) relative to reference baseline."
                    ),
                    evidence_type=EvidenceType.BEHAVIORAL,
                    narrative=(
                        f"Behavioral responses over {len(probe_battery.images)} reference probes indicate "
                        f"functional drift from reference baseline."
                    ),
                    methodology="Behavioral fingerprint vector cosine and Hungarian match distance.",
                    metrics={"drift_distance": distance, "drift_lower": drift_lower, "drift_upper": drift_upper},
                    baseline_comparison={"distance": distance, "comparison_details": comp_res},
                    recommended_disposition=Disposition.REVIEW,
                    limitations=[
                        "Moderate drift is typical of quantization (FP32 -> INT8) or domain fine-tuning.",
                    ],
                    evidence_store=evidence_store,
                    reproducibility_info={"battery_hash": probe_battery.battery_hash},
                )
                findings.append(finding)

        # 3. Isolated parameter integrity check (when white-box is accessible, even without reference)
        if candidate_model.access_level != ModelAccessLevel.BLACK_BOX:
            try:
                stats = candidate_model.get_parameter_statistics()
                anomalous_layers: List[str] = []
                for s in stats:
                    # Check for dead layers (all zeros or high sparsity)
                    if s.sparsity_ratio > 0.95 and s.total_elements > 10:
                        anomalous_layers.append(f"{s.layer_name} (sparsity {s.sparsity_ratio:.2f})")
                if anomalous_layers:
                    finding = self.create_finding(
                        asset_id=ass_id,
                        session_id=sess_id,
                        severity=SeverityLevel.LOW,
                        confidence=0.60,
                        title="Anomalous Parameter Sparsity Observed",
                        description=f"Extremely high parameter sparsity (>95%) in layers: {', '.join(anomalous_layers[:3])}.",
                        evidence_type=EvidenceType.STATISTICAL,
                        narrative="Suspicious sparsity may indicate aggressive pruning or uninitialized weights.",
                        methodology="Single-model parameter distribution analysis.",
                        affected_assets=anomalous_layers,
                        recommended_disposition=Disposition.REVIEW,
                        evidence_store=evidence_store,
                    )
                    findings.append(finding)
            except Exception:
                pass

        return findings
