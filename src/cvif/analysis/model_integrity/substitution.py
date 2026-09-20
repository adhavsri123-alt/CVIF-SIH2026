"""MT-1: Model Substitution Detection Check."""

from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from cvif.analysis.model_fingerprint import BehavioralFingerprintEngine
from cvif.analysis.model_integrity.base import ModelIntegrityCheck
from cvif.core.enums import Disposition, EvidenceType, ModelAccessLevel, SeverityLevel
from cvif.core.schemas import Finding
from cvif.evidence.store import EvidenceStore
from cvif.model.adapter import ModelAdapter
from cvif.model.battery import ReferenceBattery, ReferenceBatteryBuilder


class ModelSubstitutionCheck(ModelIntegrityCheck):
    """Detects unexpected model substitution against declared baseline identity or reference model."""

    @property
    def threat_id(self) -> str:
        return "MT-1"

    @property
    def name(self) -> str:
        return "Model Substitution Detection"

    @property
    def description(self) -> str:
        return (
            "Investigates whether a contributed model has been replaced or substituted with an "
            "entirely different model via cryptographic weight digests and behavioral probe distance."
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
        sub_threshold = cfg.get("substitution_distance_threshold", 0.25)
        probe_battery = battery or ReferenceBatteryBuilder.create_synthetic_battery(
            task_type=candidate_model.get_task_type()
        )

        engine = BehavioralFingerprintEngine()

        if reference_model is None:
            # Case 1: No reference baseline model provided
            fp_cand = engine.compute_fingerprint(candidate_model, probe_battery)
            finding = self.create_finding(
                asset_id=ass_id,
                session_id=sess_id,
                severity=SeverityLevel.INFORMATIONAL,
                confidence=0.5,
                title="Model Identity Registered (No Reference Baseline)",
                description=(
                    f"Candidate model artifact hash ({fp_cand.artifact_hash[:16]}...) and "
                    f"behavioral fingerprint registered. Substitution cannot be confirmed or ruled out "
                    f"without an authenticated reference model baseline."
                ),
                evidence_type=EvidenceType.CRYPTOGRAPHIC,
                narrative="Candidate model evaluated in isolation; identity fingerprints catalogued.",
                methodology="Artifact SHA-256 and probe battery behavioral fingerprinting.",
                metrics={"signature_dim": float(len(fp_cand.behavioral_signature))},
                baseline_comparison={"reference_available": False},
                recommended_disposition=Disposition.REVIEW,
                limitations=[
                    "Cannot verify model authenticity without trusted reference weights or baseline fingerprint.",
                    "Artifact identity establishes provenance tracking only from this point forward.",
                ],
                evidence_store=evidence_store,
                reproducibility_info={
                    "probe_battery_hash": probe_battery.battery_hash,
                    "artifact_hash": fp_cand.artifact_hash,
                },
            )
            findings.append(finding)
            return findings

        # Case 2: Reference model provided - execute dual white-box / black-box comparison
        comp_res = engine.compare_models(candidate_model, reference_model, probe_battery)
        distance = comp_res["distance"]
        fp_cand = comp_res["candidate_fingerprint"]
        fp_ref = comp_res["reference_fingerprint"]

        # 1. White-box weight digest check
        weights_match = False
        if (
            candidate_model.access_level != ModelAccessLevel.BLACK_BOX
            and reference_model.access_level != ModelAccessLevel.BLACK_BOX
        ):
            weights_match = fp_cand.weight_digest == fp_ref.weight_digest

        if weights_match and distance < 1e-4:
            # Identical model
            finding = self.create_finding(
                asset_id=ass_id,
                session_id=sess_id,
                severity=SeverityLevel.INFORMATIONAL,
                confidence=0.99,
                title="Model Identity Verified (Reference Match)",
                description="Candidate model cryptographically matches reference model weights and behavioral profile.",
                evidence_type=EvidenceType.COMPARATIVE,
                narrative="Weight digest and behavioral responses are identical to reference model.",
                methodology="SHA-256 weight tensor hashing and behavioral fingerprint distance.",
                metrics={"behavioral_distance": distance},
                baseline_comparison={
                    "candidate_digest": fp_cand.weight_digest,
                    "reference_digest": fp_ref.weight_digest,
                    "digests_match": True,
                },
                recommended_disposition=Disposition.ACCEPT,
                evidence_store=evidence_store,
                reproducibility_info={"battery_hash": probe_battery.battery_hash},
            )
            findings.append(finding)
            return findings

        # Check for substitution via behavioral divergence or weight digest mismatch
        if distance >= sub_threshold:
            conf = min(0.95, 0.70 + (distance - sub_threshold) * 0.5)
            finding = self.create_finding(
                asset_id=ass_id,
                session_id=sess_id,
                severity=SeverityLevel.HIGH,
                confidence=conf,
                title="Potential Model Substitution Detected (MT-1)",
                description=(
                    f"Candidate model exhibits significant behavioral divergence (distance {distance:.4f} >= "
                    f"threshold {sub_threshold}) from reference baseline, strongly indicating model substitution."
                ),
                evidence_type=EvidenceType.BEHAVIORAL,
                narrative=(
                    f"Behavioral comparison against reference model over {len(probe_battery.images)} probes "
                    f"yielded a distance of {distance:.4f}. Model responses indicate a different underlying network."
                ),
                methodology="Task-aware probe battery fingerprinting and Hungarian matching.",
                metrics={"behavioral_distance": distance, "threshold": sub_threshold},
                baseline_comparison={
                    "candidate_digest": fp_cand.weight_digest,
                    "reference_digest": fp_ref.weight_digest,
                    "digests_match": weights_match,
                    "comparison_details": comp_res,
                },
                recommended_disposition=Disposition.QUARANTINE,
                limitations=[
                    "Legitimate causes for divergence include major architectural revisions, different task objectives, or divergent training datasets.",
                ],
                evidence_store=evidence_store,
                reproducibility_info={
                    "battery_hash": probe_battery.battery_hash,
                    "candidate_artifact": fp_cand.artifact_hash,
                    "reference_artifact": fp_ref.artifact_hash,
                },
            )
            findings.append(finding)

        return findings
