"""Audit ledger verification endpoints."""

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, status

from cvif.api.dependencies import get_runtime_context, resolve_api_path, verify_api_key
from cvif.api.schemas import AuditArchiveInfo, AuditVerifyRequest, AuditVerifyResponse
from cvif.audit.logger import AuditLogger
from cvif.cli.commands.common import RuntimeContext
from cvif.core.exceptions import TamperDetectedError
from cvif.crypto.chain import ArchiveVerificationResult

router = APIRouter(prefix="/audit", tags=["Audit Ledger"])


@router.post(
    "/verify",
    response_model=AuditVerifyResponse,
    summary="Verify Audit Ledger Integrity",
    description="Verify the monotonic SHA-256 hash linkage of the tamper-evident audit ledger and sealed archive.",
)
def verify_audit_chain(
    req: Optional[AuditVerifyRequest] = None,
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> AuditVerifyResponse:
    target_log: Path
    if req and req.log_file:
        target_log = resolve_api_path(req.log_file, must_exist=True)
        archive_dir = target_log.parent / "archive"
    else:
        target_log = ctx.config.audit.audit_log_path
        archive_dir = ctx.config.audit.audit_log_path.parent / "archive"

    if not target_log.is_file():
        raise FileNotFoundError(f"Audit log file not found: {target_log}")

    logger = AuditLogger(target_log, auto_verify_on_init=False, archive_dir=archive_dir)
    chain_res = logger.verify_chain()
    archive_res = getattr(logger, "verify_archive", lambda: None)()

    archive_info: Optional[AuditArchiveInfo] = None
    if archive_res is not None and isinstance(archive_res, ArchiveVerificationResult):
        archive_info = AuditArchiveInfo(
            present=True,
            verified=archive_res.is_valid,
            archive_file=archive_res.archive_file,
            manifest_file=archive_res.manifest_file,
            expected_sha256=archive_res.expected_sha256,
            actual_sha256=archive_res.actual_sha256,
            total_events=archive_res.total_events,
            documented_discontinuities=archive_res.documented_discontinuities,
            error_message=archive_res.error_message,
        )

    # If active chain has tampering
    if not chain_res.is_valid:
        raise TamperDetectedError(
            f"Audit ledger tampering detected at block #{chain_res.failed_event_index}: {chain_res.error_message}",
            details={
                "broken_index": chain_res.failed_event_index,
                "log_file": str(target_log),
                "total_events": chain_res.total_events,
            },
        )

    # If archive manifest check has tampering
    if archive_info and not archive_info.verified:
        raise TamperDetectedError(
            f"Historical archive tampering detected: {archive_info.error_message}",
            details={
                "archive_file": archive_info.archive_file,
                "expected_sha256": archive_info.expected_sha256,
                "actual_sha256": archive_info.actual_sha256,
            },
        )

    return AuditVerifyResponse(
        verified=True,
        broken_index=None,
        total_events=chain_res.total_events,
        verified_events=chain_res.verified_events,
        error_message=None,
        log_file=str(target_log),
        status="VALID",
        active_epoch=1,
        archive=archive_info,
    )
