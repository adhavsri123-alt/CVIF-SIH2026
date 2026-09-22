"""Session lifecycle management endpoints."""

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends

from cvif.api.dependencies import get_runtime_context, verify_api_key
from cvif.api.schemas import CreateSessionRequest, CreateSessionResponse
from cvif.cli.commands.common import RuntimeContext
from cvif.core.enums import AssetType, SessionStatus
from cvif.core.schemas import AnalysisSession, AssetRegistration, HashManifest

router = APIRouter(prefix="/sessions", tags=["Session Management"])


@router.post(
    "/create",
    response_model=CreateSessionResponse,
    summary="Create New Assessment Session",
    description=(
        "Generate a new, empty assessment session that is fully persisted in "
        "the catalogue database.  The session starts with status INITIALIZING, "
        "no findings, no executed analyses, and no verdict.  Subsequent "
        "Dataset / Model / Inference / Distribution / Evidence / Assurance "
        "executions can target this session_id to accumulate results."
    ),
)
def create_session(
    req: CreateSessionRequest = CreateSessionRequest(),
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> CreateSessionResponse:
    now = datetime.now(timezone.utc)
    session_id = uuid4()
    placeholder_asset_id = uuid4()

    # Create a minimal placeholder asset to satisfy the NOT-NULL FK constraint
    # on sessions.asset_id.  This mirrors the fallback-asset pattern already
    # used in DatabaseManager.update_session_section.
    placeholder_asset = AssetRegistration(
        asset_id=placeholder_asset_id,
        asset_type=AssetType.DATASET,
        format="pending",
        hash_manifest=HashManifest(),
        total_size_bytes=0,
    )
    ctx.db.save_asset(placeholder_asset)

    # Persist the empty session
    session = AnalysisSession(
        session_id=session_id,
        asset_id=placeholder_asset_id,
        status=SessionStatus.INITIALIZING,
        requested_analyses=[],
        executed_analyses=[],
        skipped_analyses=[],
        start_time=now,
        end_time=None,
        duration_ms=None,
        findings=[],
        verdict=None,
        operator_id=req.operator_id or "cvif_api",
        execution_environment={},
    )
    ctx.db.save_session(session)

    return CreateSessionResponse(
        session_id=session_id,
        status=SessionStatus.INITIALIZING.value,
        created_at=now.isoformat(),
    )
