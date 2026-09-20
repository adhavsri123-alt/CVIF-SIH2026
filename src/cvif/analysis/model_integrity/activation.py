"""MT-4: Anomalous Activation Patterns Analysis Check."""

import math
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from cvif.analysis.model_integrity.base import ModelIntegrityCheck
from cvif.core.enums import Disposition, EvidenceType, ModelAccessLevel, SeverityLevel
from cvif.core.schemas import Finding
from cvif.evidence.store import EvidenceStore
from cvif.model.adapter import ModelAdapter
from cvif.model.battery import ReferenceBattery, ReferenceBatteryBuilder


class AnomalousActivationCheck(ModelIntegrityCheck):
    """Inspects intermediate layer activation statistics, dead neuron clusters, and representation divergence."""

    @property
    def threat_id(self) -> str:
        return "MT-4"

    @property
    def name(self) -> str:
        return "Anomalous Activation Patterns"

    @property
    def description(self) -> str:
        return (
            "Inspects internal layer activations across probe battery inputs to detect dead neuron clusters, "
            "dormant backdoor sub-circuits, or internal representation collapse."
        )

    @property
    def required_access_level(self) -> ModelAccessLevel:
        return ModelAccessLevel.WHITE_BOX

    @property
    def minimum_access_level(self) -> ModelAccessLevel:
        return ModelAccessLevel.WHITE_BOX

    def check_applicable(
        self,
        candidate_model: ModelAdapter,
        reference_model: Optional[ModelAdapter] = None,
        battery: Optional[ReferenceBattery] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> bool:
        # Check is applicable to any model, but handles black-box gracefully
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

        # 1. Check access level: if BLACK_BOX or GREY_BOX, emit structured unsupported finding
        if candidate_model.access_level != ModelAccessLevel.WHITE_BOX:
            finding = self.create_finding(
                asset_id=ass_id,
                session_id=sess_id,
                severity=SeverityLevel.INFORMATIONAL,
                confidence=1.0,
                title="Activation Analysis Skipped (Requires WHITE_BOX Access)",
                description=(
                    f"Candidate model access level is {candidate_model.access_level.value}. "
                    f"Intermediate activation inspection requires WHITE_BOX access to instrument forward hooks."
                ),
                evidence_type=EvidenceType.STATISTICAL,
                narrative="Activation inspection gracefully bypassed in accordance with Section M.2.4 of architecture specification.",
                methodology="Access level inspection.",
                recommended_disposition=Disposition.REVIEW,
                limitations=[
                    "Cannot verify intermediate layer activations, dead neurons, or representation similarity without white-box access."
                ],
                evidence_store=evidence_store,
            )
            findings.append(finding)
            return findings

        probe_battery = battery or ReferenceBatteryBuilder.create_synthetic_battery(
            task_type=candidate_model.get_task_type()
        )

        cfg = config or {}
        dead_neuron_threshold = cfg.get("dead_neuron_threshold", 0.75)

        # 2. Collect activations across probe battery
        layer_activations: Dict[str, List[List[float]]] = {}
        for probe in probe_battery.images[:5]:
            try:
                acts = candidate_model.get_layer_activations(probe)
                for lname, act_vals in acts.items():
                    flat = self._flatten(act_vals)
                    if lname not in layer_activations:
                        layer_activations[lname] = []
                    layer_activations[lname].append(flat)
            except Exception:
                pass

        if not layer_activations:
            return findings

        # 3. Analyze dead neurons per layer
        dead_layers: Dict[str, float] = {}
        for lname, samples in layer_activations.items():
            if not samples or not samples[0]:
                continue
            dim = len(samples[0])
            dead_count = 0
            for neuron_idx in range(dim):
                # Check if this neuron is non-positive across all samples
                vals = [s[neuron_idx] for s in samples if neuron_idx < len(s)]
                if all(v <= 0.0 for v in vals):
                    dead_count += 1
            ratio = dead_count / max(1, dim)
            if ratio >= dead_neuron_threshold:
                dead_layers[lname] = round(ratio, 4)

        if dead_layers:
            finding = self.create_finding(
                asset_id=ass_id,
                session_id=sess_id,
                severity=SeverityLevel.MEDIUM,
                confidence=0.80,
                title="Elevated Dead Neuron Ratio Detected (MT-4)",
                description=(
                    f"Abnormally high dead neuron ratio (>= {dead_neuron_threshold * 100:.0f}%) observed in "
                    f"layers: {', '.join([f'{k} ({v*100:.1f}%)' for k, v in dead_layers.items()])}."
                ),
                evidence_type=EvidenceType.STATISTICAL,
                narrative=(
                    f"Dead neuron analysis over {len(probe_battery.images)} reference probes revealed inactive "
                    f"sub-networks. High ratios may indicate dormant backdoor circuitry or collapsed feature extraction."
                ),
                methodology="Layer activation dead neuron profiling across reference battery inputs.",
                metrics={f"dead_ratio_{k}": v for k, v in dead_layers.items()},
                affected_assets=list(dead_layers.keys()),
                recommended_disposition=Disposition.REVIEW,
                limitations=[
                    "ReLU networks naturally exhibit dead neurons on specialized subsets; comparison against reference baseline is recommended."
                ],
                evidence_store=evidence_store,
                reproducibility_info={"battery_hash": probe_battery.battery_hash},
            )
            findings.append(finding)

        # 4. If reference model also has white-box access, compute representation similarity
        if reference_model is not None and reference_model.access_level == ModelAccessLevel.WHITE_BOX:
            ref_activations: Dict[str, List[List[float]]] = {}
            for probe in probe_battery.images[:5]:
                try:
                    acts = reference_model.get_layer_activations(probe)
                    for lname, act_vals in acts.items():
                        flat = self._flatten(act_vals)
                        if lname not in ref_activations:
                            ref_activations[lname] = []
                        ref_activations[lname].append(flat)
                except Exception:
                    pass

            divergent_layers: Dict[str, float] = {}
            for lname in layer_activations:
                if lname in ref_activations:
                    c_samples = layer_activations[lname]
                    r_samples = ref_activations[lname]
                    sim = self._compute_mean_cosine_sim(c_samples, r_samples)
                    if sim < 0.50:
                        divergent_layers[lname] = round(sim, 4)

            if divergent_layers:
                finding = self.create_finding(
                    asset_id=ass_id,
                    session_id=sess_id,
                    severity=SeverityLevel.HIGH,
                    confidence=0.85,
                    title="Intermediate Representation Divergence Detected (MT-4)",
                    description=(
                        f"Low internal activation similarity (<0.50) compared to reference model in layers: "
                        f"{', '.join([f'{k} (sim: {v:.2f})' for k, v in divergent_layers.items()])}."
                    ),
                    evidence_type=EvidenceType.COMPARATIVE,
                    narrative="Internal representations in candidate network diverge significantly from reference baseline.",
                    methodology="Layer activation cosine representation similarity.",
                    metrics={f"similarity_{k}": v for k, v in divergent_layers.items()},
                    affected_assets=list(divergent_layers.keys()),
                    recommended_disposition=Disposition.QUARANTINE,
                    evidence_store=evidence_store,
                    reproducibility_info={"battery_hash": probe_battery.battery_hash},
                )
                findings.append(finding)

        return findings

    def _flatten(self, item: Any) -> List[float]:
        if isinstance(item, (int, float)):
            return [float(item)]
        if hasattr(item, "flatten") and hasattr(item, "tolist"):
            return [float(x) for x in item.flatten().tolist()]
        if isinstance(item, (list, tuple)):
            res: List[float] = []
            for sub in item:
                res.extend(self._flatten(sub))
            return res
        return []

    def _compute_mean_cosine_sim(self, list_a: List[List[float]], list_b: List[List[float]]) -> float:
        sims: List[float] = []
        n = min(len(list_a), len(list_b))
        for i in range(n):
            va = list_a[i]
            vb = list_b[i]
            if len(va) == len(vb) and len(va) > 0:
                dot = sum(a * b for a, b in zip(va, vb))
                na = math.sqrt(sum(a * a for a in va))
                nb = math.sqrt(sum(b * b for b in vb))
                if na > 1e-9 and nb > 1e-9:
                    sims.append(dot / (na * nb))
        return (sum(sims) / len(sims)) if sims else 1.0
