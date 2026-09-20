"""Threat check IT-3 and IT-5: Replay, Injection, and Sequence Monotonicity Analysis."""

from typing import Any, Dict, List, Optional
from uuid import UUID

from cvif.analysis.inference_provenance.base import InferenceProvenanceCheck
from cvif.core.schemas import Finding, InferenceRecord
from cvif.evidence.store import EvidenceStore


class ReplayProtectionCheck(InferenceProvenanceCheck):
    """Detects replay attacks, sequence number regressions, timing skew, and packet drops (IT-3, IT-5)."""

    @property
    def threat_id(self) -> str:
        return "IT-3"

    @property
    def name(self) -> str:
        return "Replay and Sequence Monotonicity Analysis"

    @property
    def description(self) -> str:
        return (
            "Enforces strict nonce uniqueness, per-session sequence monotonicity, and "
            "allowable timestamp tolerance to detect record injection and frame suppression."
        )

    def check_applicable(self, record: InferenceRecord, config: Optional[Dict[str, Any]] = None) -> bool:
        return bool(record.nonce and record.sequence_number is not None)

    def run(
        self,
        record: InferenceRecord,
        verifier: Any,
        session_id: Optional[UUID] = None,
        evidence_store: Optional[EvidenceStore] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        cfg = config or {}
        ref_time = cfg.get("reference_time")
        sess_id = session_id or record.session_id

        res = verifier.verify_record(
            record=record,
            reference_time=ref_time,
            enforce_replay_checks=True,
        )

        replay_findings = [f for f in res.findings if f.threat_id in ("IT-3", "IT-5")]
        return replay_findings
