"""Evidence store inspection, cryptographic verification, and export endpoints."""

import json
from pathlib import Path
from typing import Optional
from uuid import UUID
import zipfile

from fastapi import APIRouter, Depends, Query, status

from cvif.api.dependencies import get_runtime_context, resolve_api_path, verify_api_key
from cvif.api.schemas import (
    EvidenceConsistencyResponse,
    EvidenceExportRequest,
    EvidenceExportResponse,
    EvidenceListResponse,
    EvidenceRecordSummary,
    EvidenceVerifyRequest,
)
from cvif.cli.commands.common import RuntimeContext
from cvif.core.exceptions import TamperDetectedError
from cvif.core.schemas import EvidenceRecord
from cvif.crypto.hashing import sha256_bytes, sha256_file

router = APIRouter(prefix="/evidence", tags=["Evidence Store"])


@router.get(
    "",
    response_model=EvidenceListResponse,
    summary="List Indexed Evidence Records",
    description="Query relational SQLite metadata index for evidence records matching optional filter parameters.",
)
def list_evidence(
    session_id: Optional[str] = Query(None, description="Filter by session UUID or prefix."),
    finding_id: Optional[str] = Query(None, description="Filter by finding UUID or prefix."),
    threat_id: Optional[str] = Query(None, description="Filter by threat taxonomy ID (e.g. DT-1, MT-3)."),
    evidence_type: Optional[str] = Query(None, description="Filter by evidence type (e.g. STATISTICAL, ARTIFACT)."),
    limit: int = Query(100, ge=1, le=1000, description="Pagination limit."),
    offset: int = Query(0, ge=0, description="Pagination offset."),
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> EvidenceListResponse:
    if threat_id:
        rows = ctx.db.get_evidence_by_threat_id(threat_id)
        if session_id:
            s_clean = str(session_id).strip().lower()
            rows = [r for r in rows if str(r.get("session_id", "")).lower().startswith(s_clean)]
        if finding_id:
            f_clean = str(finding_id).strip().lower()
            rows = [r for r in rows if str(r.get("finding_id", "")).lower().startswith(f_clean)]
        if evidence_type:
            e_clean = str(evidence_type).strip().upper()
            rows = [r for r in rows if str(r.get("evidence_type", "")).upper().startswith(e_clean)]
    else:
        rows = ctx.db.list_evidence_records(
            session_id=session_id,
            finding_id=finding_id,
            evidence_type=evidence_type,
        )

    paged = rows[offset : offset + limit]
    summaries = []
    for r in paged:
        threat_val = r.get("threat_id")
        if not threat_val and "record_json" in r and r["record_json"]:
            try:
                rj = json.loads(r["record_json"])
                threat_val = rj.get("reproducibility_info", {}).get("threat_id")
            except Exception:
                threat_val = None

        fid = None
        if r.get("finding_id"):
            try:
                fid = UUID(str(r["finding_id"]))
            except (ValueError, TypeError):
                fid = None

        eid = UUID(str(r["evidence_id"])) if isinstance(r["evidence_id"], (str, UUID)) else r["evidence_id"]
        sid = UUID(str(r["session_id"])) if isinstance(r["session_id"], (str, UUID)) else r["session_id"]

        summaries.append(
            EvidenceRecordSummary(
                evidence_id=eid,
                session_id=sid,
                finding_id=fid,
                evidence_type=r.get("evidence_type", "UNKNOWN"),
                content_hash=r.get("content_hash", ""),
                created_at=str(r.get("created_at", "")),
                threat_id=threat_val,
            )
        )

    return EvidenceListResponse(
        total=len(rows),
        records=summaries,
    )


@router.get(
    "/{id}",
    response_model=EvidenceRecord,
    summary="Retrieve Evidence Record by ID",
    description="Fetch an EvidenceRecord by UUID, verifying its canonical SHA-256 hash and linked artifact digests.",
)
def get_evidence_by_id(
    id: str,
    verify: bool = Query(True, description="Enforce cryptographic verification of record and linked artifacts."),
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> EvidenceRecord:
    try:
        val_id = UUID(id)
    except (ValueError, TypeError, AttributeError):
        raise FileNotFoundError(f"Evidence record not found (invalid UUID format): {id}")

    record = ctx.evidence.get_evidence(val_id, verify_integrity=verify)
    if record is None:
        raise FileNotFoundError(f"Evidence record not found: {id}")
    return record


@router.post(
    "/verify",
    response_model=EvidenceConsistencyResponse,
    summary="Verify Evidence Store Consistency",
    description="Perform store-wide consistency audit cross-checking physical files against SQLite catalog digests.",
)
def verify_evidence_consistency(
    req: Optional[EvidenceVerifyRequest] = None,
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> EvidenceConsistencyResponse:
    sess_id = req.session_id if req else None
    audit_res = ctx.evidence.verify_store_consistency(session_id=sess_id)

    if not audit_res["is_consistent"]:
        raise TamperDetectedError(
            "Evidence store consistency check failed: one or more records/artifacts are missing or tampered.",
            details=audit_res,
        )

    return EvidenceConsistencyResponse(
        total_records=audit_res["total_records"],
        total_artifacts=audit_res["total_artifacts"],
        is_consistent=audit_res["is_consistent"],
        missing_records=audit_res.get("missing_records", []),
        tampered_records=audit_res.get("tampered_records", []),
        missing_artifacts=audit_res.get("missing_artifacts", []),
        tampered_artifacts=audit_res.get("tampered_artifacts", []),
        orphan_evidence=audit_res.get("orphan_evidence", []),
        orphan_artifacts=audit_res.get("orphan_artifacts", []),
    )


@router.post(
    "/export",
    response_model=EvidenceExportResponse,
    summary="Export Session Evidence Bundle",
    description="Package session evidence records and diagnostic artifacts into a tamper-evident .cvif zip archive with SHA-256 manifest.",
)
def export_evidence_bundle(
    req: EvidenceExportRequest,
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> EvidenceExportResponse:
    # 1. Pre-export consistency check
    audit_res = ctx.evidence.verify_store_consistency(session_id=req.session_id)
    if not audit_res["is_consistent"]:
        raise TamperDetectedError(
            "Cannot export session with corrupted or tampered evidence.",
            details=audit_res,
        )

    records = ctx.evidence.list_evidence_for_session(req.session_id)
    if not records:
        raise FileNotFoundError(f"No evidence records found for session: {req.session_id}")

    if req.output_path:
        dest_file = resolve_api_path(req.output_path)
    else:
        bundles_dir = ctx.config.evidence.evidence_dir / "bundles"
        bundles_dir.mkdir(parents=True, exist_ok=True)
        dest_file = bundles_dir / f"{req.session_id}_bundle.cvif"

    dest_file.parent.mkdir(parents=True, exist_ok=True)

    manifest = {
        "session_id": str(req.session_id),
        "files": {},
    }

    with zipfile.ZipFile(dest_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rec in records:
            rel_rec_path = f"evidence/{rec.evidence_id}.json"
            rec_bytes = rec.to_canonical_bytes()
            zf.writestr(rel_rec_path, rec_bytes)
            manifest["files"][rel_rec_path] = sha256_bytes(rec_bytes)

            if rec.artifacts:
                for art in rec.artifacts:
                    art_bytes = ctx.evidence.read_artifact(req.session_id, art.path, verify_integrity=True)
                    zf.writestr(art.path, art_bytes)
                    manifest["files"][art.path] = sha256_bytes(art_bytes)

        # Write manifest
        manifest_json = json.dumps(manifest, indent=2, sort_keys=True)
        zf.writestr("manifest.json", manifest_json)

    archive_digest = sha256_file(dest_file)

    return EvidenceExportResponse(
        session_id=req.session_id,
        archive_path=str(dest_file),
        total_records=len(records),
        total_files=len(manifest["files"]),
        sha256_manifest_digest=archive_digest,
    )
