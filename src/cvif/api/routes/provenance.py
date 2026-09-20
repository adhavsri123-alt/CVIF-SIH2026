"""Inference provenance verification endpoints."""

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Body, Depends, status

from cvif.api.dependencies import get_runtime_context, resolve_api_path, verify_api_key
from cvif.api.schemas import (
    ProvenanceDemoRecordRequest,
    ProvenanceDemoRecordResponse,
    ProvenanceVerifyRequest,
    ProvenanceVerifyResponse,
)
from cvif.cli.commands.common import RuntimeContext
from cvif.provenance.demo import generate_demo_inference_record, get_demo_keypair
from cvif.provenance.verifier import InferenceProvenanceVerifier

router = APIRouter(prefix="/provenance", tags=["Inference Provenance"])


@router.post(
    "/verify",
    response_model=ProvenanceVerifyResponse,
    summary="Verify Inference Provenance",
    description="Verify cryptographic signature, contributor key identity, image digest binding, and replay nonces (IT-1 to IT-5).",
)
def verify_provenance(
    req: ProvenanceVerifyRequest,
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> ProvenanceVerifyResponse:
    raw_image_resolved: Optional[Path] = None
    if req.raw_image_path:
        raw_image_resolved = resolve_api_path(req.raw_image_path, must_exist=True)

    tolerance = req.tolerance_seconds if req.tolerance_seconds is not None else 86400.0
    enforce_replay = req.enforce_replay_checks if req.enforce_replay_checks is not None else True

    verifier = InferenceProvenanceVerifier(
        key_store=ctx.keystore,
        db_manager=ctx.db,
        tolerance_seconds=tolerance,
    )

    res = verifier.verify_record(
        record=req.record,
        raw_image=raw_image_resolved,
        registered_model_digest=req.expected_model_digest,
        enforce_replay_checks=enforce_replay,
    )

    producer = req.record.producer_id or req.record.signing_key_id or "Unknown"

    return ProvenanceVerifyResponse(
        record_id=req.record.record_id,
        session_id=req.record.session_id,
        contributor_id=producer,
        status=res.status.value,
        is_valid=res.is_valid,
        findings_count=len(res.findings or []),
        findings=res.findings or [],
        details=res.details or {},
    )


@router.post(
    "/demo-record",
    response_model=ProvenanceDemoRecordResponse,
    summary="Generate Fresh Demo Inference Record",
    description="Generate a fresh, legitimately signed InferenceRecord (or tampered record) using local Ed25519 signing keys for demonstration and testing.",
)
def generate_demo_record(
    req: ProvenanceDemoRecordRequest = Body(default_factory=ProvenanceDemoRecordRequest),
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> ProvenanceDemoRecordResponse:
    # Ensure demo public key is registered in ctx.keystore
    _, pub_key, key_id, producer_id = get_demo_keypair()
    if not ctx.keystore.get_key_record(key_id):
        ctx.keystore.register_public_key(
            key_id=key_id,
            owner_entity=producer_id,
            public_key=pub_key,
        )

    record = generate_demo_inference_record(
        db_manager=ctx.db,
        session_id=req.session_id,
        new_session=req.new_session,
        tampered=req.tampered,
    )

    msg = (
        f"Fresh demo record generated (Seq #{record.sequence_number}, Nonce: {record.nonce[:8]}..., Session: {record.session_id}). Ready for verification."
        if not req.tampered
        else f"Tampered demo record generated (Confidence altered to 0.9999 post-signing, Seq #{record.sequence_number}). Ready for tamper detection verification."
    )

    return ProvenanceDemoRecordResponse(
        record=record,
        sequence_number=record.sequence_number,
        is_tampered=req.tampered,
        message=msg,
    )
