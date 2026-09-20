"""Threat check IT-2: Model and Preprocessing Configuration Substitution Analysis."""

from typing import Any, Dict, List, Optional
from uuid import UUID

from cvif.analysis.inference_provenance.base import InferenceProvenanceCheck
from cvif.core.schemas import Finding, InferenceRecord
from cvif.evidence.store import EvidenceStore


class ModelSubstitutionCheck(InferenceProvenanceCheck):
    """Detects model substitution or unauthorized preprocessing alterations (IT-2)."""

    @property
    def threat_id(self) -> str:
        return "IT-2"

    @property
    def name(self) -> str:
        return "Model and Preprocessing Substitution Analysis"

    @property
    def description(self) -> str:
        return (
            "Cross-references record model weight digest and preprocessing configuration hash "
            "against approved baseline catalog registrations to detect substitution attacks."
        )

    def check_applicable(self, record: InferenceRecord, config: Optional[Dict[str, Any]] = None) -> bool:
        return bool(record.model_id and record.model_weight_digest)

    def run(
        self,
        record: InferenceRecord,
        verifier: Any,
        session_id: Optional[UUID] = None,
        evidence_store: Optional[EvidenceStore] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        cfg = config or {}
        registered_model_digest = cfg.get("registered_model_digest")
        registered_prep_hash = cfg.get("registered_preprocessing_hash")
        sess_id = session_id or record.session_id

        res = verifier.verify_record(
            record=record,
            registered_model_digest=registered_model_digest,
            registered_preprocessing_hash=registered_prep_hash,
            enforce_replay_checks=False,
        )

        substitution_findings = [f for f in res.findings if f.threat_id == "IT-2"]
        return substitution_findings
