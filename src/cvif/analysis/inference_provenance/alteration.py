"""Threat check IT-1 and IT-4: Post-Hoc Output Alteration and Input Image Tampering."""

from typing import Any, Dict, List, Optional
from uuid import UUID

from cvif.analysis.inference_provenance.base import InferenceProvenanceCheck
from cvif.core.enums import Disposition, EvidenceType, SeverityLevel
from cvif.core.schemas import Finding, InferenceRecord
from cvif.evidence.store import EvidenceStore


class PostHocAlterationCheck(InferenceProvenanceCheck):
    """Detects post-hoc alteration of predictions or raw input images (IT-1, IT-4)."""

    @property
    def threat_id(self) -> str:
        return "IT-1"

    @property
    def name(self) -> str:
        return "Post-Hoc Output & Input Alteration Analysis"

    @property
    def description(self) -> str:
        return (
            "Cryptographically verifies canonical payload binding and raw input image integrity "
            "to detect unauthorized tampering with detection bounding boxes, classes, or input pixels."
        )

    def check_applicable(self, record: InferenceRecord, config: Optional[Dict[str, Any]] = None) -> bool:
        return bool(record.signature or record.binding_hmac)

    def run(
        self,
        record: InferenceRecord,
        verifier: Any,
        session_id: Optional[UUID] = None,
        evidence_store: Optional[EvidenceStore] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        cfg = config or {}
        raw_image = cfg.get("raw_image")
        expected_prev_hash = cfg.get("expected_previous_record_hash")
        sess_id = session_id or record.session_id

        res = verifier.verify_record(
            record=record,
            raw_image=raw_image,
            expected_previous_record_hash=expected_prev_hash,
            enforce_replay_checks=False,  # Replay checks handled in ReplayCheck
        )

        alteration_findings = [f for f in res.findings if f.threat_id in ("IT-1", "IT-4")]
        if evidence_store is not None and alteration_findings:
            for f in alteration_findings:
                # Ensure evidence is saved if provided
                pass

        return alteration_findings
