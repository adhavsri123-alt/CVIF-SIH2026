"""Assurance aggregation and holistic verdict evaluation endpoints."""

from fastapi import APIRouter, Depends, status

from cvif.analysis.assurance.orchestrator import AssuranceOrchestrator
from cvif.api.dependencies import get_runtime_context, verify_api_key
from cvif.api.schemas import AssessRequest
from cvif.cli.commands.common import RuntimeContext
from cvif.core.schemas import AssuranceVerdict

router = APIRouter(tags=["Assurance Aggregation"])


@router.post(
    "/assess",
    response_model=AssuranceVerdict,
    summary="Synthesize Assurance Verdict",
    description="Aggregate multi-dimensional findings for an analysis session, evaluate Weakest-Link Critical Vetoes and Noisy-OR composite risk, and emit authoritative AssuranceVerdict.",
)
def evaluate_assurance(
    req: AssessRequest,
    ctx: RuntimeContext = Depends(get_runtime_context),
    _: None = Depends(verify_api_key),
) -> AssuranceVerdict:
    session = ctx.db.get_session(req.session_id)
    if session is None:
        raise FileNotFoundError(f"Session not found in catalogue database: {req.session_id}")

    orchestrator = AssuranceOrchestrator(
        config=ctx.config.assurance,
        db_manager=ctx.db,
        audit_logger=ctx.audit,
    )

    verdict = orchestrator.evaluate_session(session, operator_id="cvif_api")
    return verdict
