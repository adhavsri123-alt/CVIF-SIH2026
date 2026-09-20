"""System diagnostics, health checks, and version endpoints."""

from pathlib import Path
import platform

from fastapi import APIRouter, Depends, status

from cvif.api.dependencies import get_runtime_context, verify_api_key
from cvif.api.schemas import (
    AuditArchiveInfo,
    AuditChainHealth,
    HealthStatusResponse,
    ServiceHealth,
    VersionResponse,
)
from cvif.cli.commands.common import RuntimeContext
from cvif.crypto.chain import ArchiveVerificationResult
from cvif.version import __schema_version__, __version__

router = APIRouter(tags=["System & Diagnostics"])


@router.get(
    "/health",
    response_model=HealthStatusResponse,
    summary="System Health & Diagnostic Status",
    description="Check connectivity to database, evidence store, trust store, and audit ledger integrity.",
)
def get_health(
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> HealthStatusResponse:
    # 1. Audit chain & archive
    chain_res = ctx.audit.verify_chain()
    chain_valid = chain_res.is_valid

    archive_res = getattr(ctx.audit, "verify_archive", lambda: None)()
    archive_valid = True
    archive_info: Optional[AuditArchiveInfo] = None

    if archive_res is not None and isinstance(archive_res, ArchiveVerificationResult):
        archive_valid = archive_res.is_valid
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

    audit_healthy = chain_valid and archive_valid

    # 2. Database
    db_accessible = False
    try:
        with ctx.db.transaction() as cur:
            cur.execute("SELECT 1;")
            db_accessible = True
    except Exception:
        db_accessible = False

    # 3. Storage
    storage_ok = (
        ctx.config.storage.data_dir.exists()
        and ctx.config.evidence.evidence_dir.exists()
    )

    is_healthy = audit_healthy and db_accessible and storage_ok
    status_str = "HEALTHY" if is_healthy else "DEGRADED"

    return HealthStatusResponse(
        status=status_str,
        audit_chain=AuditChainHealth(
            intact=audit_healthy,
            broken_index=chain_res.failed_event_index,
            total_events=chain_res.total_events,
            verified_events=chain_res.verified_events,
            log_file=str(ctx.config.audit.audit_log_path),
            active_epoch=1,
            archive=archive_info,
        ),
        database=ServiceHealth(
            accessible=db_accessible,
            path=str(ctx.config.storage.catalog_db_path),
        ),
        evidence_store=ServiceHealth(
            accessible=ctx.config.evidence.evidence_dir.is_dir(),
            directory=str(ctx.config.evidence.evidence_dir),
        ),
        truststore=ServiceHealth(
            accessible=ctx.config.keystore.keystore_dir.is_dir(),
            directory=str(ctx.config.keystore.keystore_dir),
        ),
    )


@router.get(
    "/version",
    response_model=VersionResponse,
    summary="Framework & Schema Version",
    description="Display CVIF build, schema version, runtime platform, and air-gap enforcement flag.",
)
def get_version() -> VersionResponse:
    return VersionResponse(
        version=__version__,
        schema_version=__schema_version__,
        architecture_version="0.2-REVISED",
        python_version=platform.python_version(),
        platform=platform.platform(),
        air_gap_enforced=True,
    )
