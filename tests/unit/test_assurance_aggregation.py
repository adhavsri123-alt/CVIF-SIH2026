"""Unit tests for Phase 7 Assurance Aggregation engine."""

import math
import time
from uuid import UUID, uuid4
import pytest

from cvif.analysis.assurance import (
    AssuranceAggregator,
    AssuranceOrchestrator,
    compute_finding_risk,
    evaluate_critical_veto,
    evaluate_disposition,
    map_finding_to_dimension,
    validate_finding_for_assurance,
)
from cvif.core.config import AssuranceConfig
from cvif.core.enums import AuditEventType, Disposition, SeverityLevel
from cvif.core.exceptions import SchemaValidationError
from cvif.core.schemas import AnalysisSession, AssuranceVerdict, Finding


def make_finding(
    threat_id: str = "DT-1",
    category: str = "DATA_INTEGRITY",
    severity: SeverityLevel = SeverityLevel.LOW,
    confidence: float = 0.50,
    recommended_disposition: Disposition = Disposition.REVIEW,
    asset_id: UUID = None,
    session_id: UUID = None,
    title: str = "Test Finding",
) -> Finding:
    """Helper to construct valid Finding instances for aggregation tests."""
    return Finding(
        finding_id=uuid4(),
        asset_id=asset_id or uuid4(),
        session_id=session_id or uuid4(),
        threat_id=threat_id,
        category=category,
        severity=severity,
        confidence=confidence,
        title=title,
        description=f"Automated test finding for {threat_id}",
        recommended_disposition=recommended_disposition,
    )


# =====================================================================
# A. No findings + Complete Evidence -> ACCEPT, Risk = 0.0
# =====================================================================
def test_category_a_no_findings_complete_evidence():
    aggregator = AssuranceAggregator()
    asset_id = uuid4()
    session_id = uuid4()

    verdict = aggregator.aggregate(
        asset_id=asset_id,
        session_id=session_id,
        findings=[],
        unsupported_checks=[],
    )

    assert verdict.asset_id == asset_id
    assert verdict.session_id == session_id
    assert verdict.composite_risk_score == 0.0
    assert verdict.disposition == Disposition.ACCEPT
    assert verdict.contributing_finding_ids == []
    assert verdict.unsupported_checks == []
    assert "ACCEPT" in verdict.summary
    assert "COMPLETE" in verdict.summary


# =====================================================================
# B. One LOW finding
# =====================================================================
def test_category_b_one_low_finding():
    aggregator = AssuranceAggregator()
    f = make_finding(
        threat_id="DT-1",
        category="DATA_INTEGRITY",
        severity=SeverityLevel.LOW,
        confidence=0.50,
        recommended_disposition=Disposition.ACCEPT,
    )

    # weight(LOW) = 0.20 * 0.50 = 0.10
    verdict = aggregator.aggregate(
        asset_id=f.asset_id,
        session_id=f.session_id,
        findings=[f],
        unsupported_checks=[],
    )

    assert verdict.composite_risk_score == 0.10
    assert verdict.disposition == Disposition.ACCEPT
    assert len(verdict.contributing_finding_ids) == 1
    assert verdict.contributing_finding_ids[0] == f.finding_id


# =====================================================================
# C. One HIGH finding
# =====================================================================
def test_category_c_one_high_finding():
    aggregator = AssuranceAggregator()
    f = make_finding(
        threat_id="DT-4",
        category="DATA_INTEGRITY",
        severity=SeverityLevel.HIGH,
        confidence=0.80,
        recommended_disposition=Disposition.REVIEW,
    )

    # weight(HIGH) = 0.80 * 0.80 = 0.64
    verdict = aggregator.aggregate(
        asset_id=f.asset_id,
        session_id=f.session_id,
        findings=[f],
        unsupported_checks=[],
    )

    assert verdict.composite_risk_score == 0.64
    assert verdict.disposition == Disposition.REVIEW


# =====================================================================
# D. One CRITICAL finding with confidence < 0.50 (no veto)
# =====================================================================
def test_category_d_critical_low_confidence():
    aggregator = AssuranceAggregator()
    f = make_finding(
        threat_id="MT-3",
        category="MODEL_INTEGRITY",
        severity=SeverityLevel.CRITICAL,
        confidence=0.40,
        recommended_disposition=Disposition.REVIEW,
    )

    # r_i = 1.00 * 0.40 = 0.40. Veto does NOT trigger because conf < 0.50.
    verdict = aggregator.aggregate(
        asset_id=f.asset_id,
        session_id=f.session_id,
        findings=[f],
        unsupported_checks=[],
    )

    assert verdict.composite_risk_score == 0.40
    # 0.40 >= 0.30 (review threshold) -> REVIEW
    assert verdict.disposition == Disposition.REVIEW
    assert "CRITICAL VETO TRIGGERED" not in verdict.summary


# =====================================================================
# E. One CRITICAL finding with confidence >= 0.50 (Veto fires)
# =====================================================================
def test_category_e_critical_veto():
    aggregator = AssuranceAggregator()
    f = make_finding(
        threat_id="MT-3",
        category="MODEL_INTEGRITY",
        severity=SeverityLevel.CRITICAL,
        confidence=0.85,
        recommended_disposition=Disposition.REVIEW,
    )

    verdict = aggregator.aggregate(
        asset_id=f.asset_id,
        session_id=f.session_id,
        findings=[f],
        unsupported_checks=[],
    )

    # Veto triggered -> QUARANTINE, risk >= 0.70, r_i = 1.0 * 0.85 = 0.85
    assert verdict.composite_risk_score == 0.85
    assert verdict.disposition == Disposition.QUARANTINE
    assert "CRITICAL VETO TRIGGERED" in verdict.summary


# =====================================================================
# F. Explicit QUARANTINE Recommendation
# =====================================================================
def test_category_f_explicit_quarantine_recommendation():
    aggregator = AssuranceAggregator()
    f = make_finding(
        threat_id="IT-3",
        category="INFERENCE_PROVENANCE",
        severity=SeverityLevel.MEDIUM,
        confidence=0.20,
        recommended_disposition=Disposition.QUARANTINE,
    )

    verdict = aggregator.aggregate(
        asset_id=f.asset_id,
        session_id=f.session_id,
        findings=[f],
        unsupported_checks=[],
    )

    # Explicit QUARANTINE recommendation triggers veto floor 0.70
    assert verdict.disposition == Disposition.QUARANTINE
    assert verdict.composite_risk_score >= 0.70


# =====================================================================
# G. Multiple findings in same dimension (Noisy-OR)
# =====================================================================
def test_category_g_noisy_or_same_dimension():
    aggregator = AssuranceAggregator()
    # Two MEDIUM findings: w=0.50, conf=0.80 -> r = 0.40 each
    f1 = make_finding(threat_id="MT-2", category="MODEL_INTEGRITY", severity=SeverityLevel.MEDIUM, confidence=0.80)
    f2 = make_finding(threat_id="MT-4", category="MODEL_INTEGRITY", severity=SeverityLevel.MEDIUM, confidence=0.80)

    # Noisy-OR: 1 - (1 - 0.40)(1 - 0.40) = 1 - 0.36 = 0.64
    verdict = aggregator.aggregate(
        asset_id=f1.asset_id,
        session_id=f1.session_id,
        findings=[f1, f2],
        unsupported_checks=[],
    )

    # Max individual risk is 0.40, but dimension score is 0.64
    # Weighted sum: W_model (0.35) * 0.64 = 0.224
    # Composite risk = max(max(r_i), sum(W*R)) = max(0.40, 0.224) = 0.40
    # Dimensional score in narrative is 0.64
    dim_scores, _ = aggregator.compute_dimensional_scores([f1, f2])
    assert dim_scores["model_integrity"] == 0.64
    assert verdict.composite_risk_score == 0.40
    assert verdict.disposition == Disposition.REVIEW


# =====================================================================
# H. Findings across dimensions
# =====================================================================
def test_category_h_findings_across_dimensions():
    aggregator = AssuranceAggregator()
    f_data = make_finding(threat_id="DT-1", category="DATA_INTEGRITY", severity=SeverityLevel.MEDIUM, confidence=0.60)
    f_model = make_finding(threat_id="MT-1", category="MODEL_INTEGRITY", severity=SeverityLevel.HIGH, confidence=0.70)
    f_shift = make_finding(threat_id="DS-1", category="DISTRIBUTION_SHIFT", severity=SeverityLevel.LOW, confidence=0.50)

    verdict = aggregator.aggregate(
        asset_id=f_data.asset_id,
        session_id=f_data.session_id,
        findings=[f_data, f_model, f_shift],
        unsupported_checks=[],
    )

    dim_scores, _ = aggregator.compute_dimensional_scores([f_data, f_model, f_shift])
    assert dim_scores["data_integrity"] > 0.0
    assert dim_scores["model_integrity"] > 0.0
    assert dim_scores["distribution_shift"] > 0.0
    assert dim_scores["inference_provenance"] == 0.0
    assert len(verdict.contributing_finding_ids) == 3


# =====================================================================
# I. Noisy-OR Monotonicity
# =====================================================================
def test_category_i_noisy_or_monotonicity():
    aggregator = AssuranceAggregator()
    f1 = make_finding(threat_id="DS-1", category="DISTRIBUTION_SHIFT", severity=SeverityLevel.MEDIUM, confidence=0.50)
    f2 = make_finding(threat_id="DS-2", category="DISTRIBUTION_SHIFT", severity=SeverityLevel.MEDIUM, confidence=0.50)
    f3 = make_finding(threat_id="DS-3", category="DISTRIBUTION_SHIFT", severity=SeverityLevel.MEDIUM, confidence=0.50)

    dim1, _ = aggregator.compute_dimensional_scores([f1])
    dim2, _ = aggregator.compute_dimensional_scores([f1, f2])
    dim3, _ = aggregator.compute_dimensional_scores([f1, f2, f3])

    assert dim1["distribution_shift"] <= dim2["distribution_shift"]
    assert dim2["distribution_shift"] <= dim3["distribution_shift"]


# =====================================================================
# J. Composite Anti-Dilution Behavior
# =====================================================================
def test_category_j_anti_dilution():
    aggregator = AssuranceAggregator()
    # 1 strong finding in distribution_shift (weight = 0.15), r = 0.80 * 0.90 = 0.72
    f_strong = make_finding(threat_id="DS-4", category="DISTRIBUTION_SHIFT", severity=SeverityLevel.HIGH, confidence=0.90)

    verdict = aggregator.aggregate(
        asset_id=f_strong.asset_id,
        session_id=f_strong.session_id,
        findings=[f_strong],
        unsupported_checks=[],
    )

    # Simple weighted sum would be 0.15 * 0.72 = 0.108 (diluted!)
    # Anti-dilution max ensures composite risk == 0.72
    assert verdict.composite_risk_score == 0.72
    assert verdict.disposition == Disposition.QUARANTINE  # >= 0.70


# =====================================================================
# K. Critical Risk Floor >= 0.70
# =====================================================================
def test_category_k_critical_risk_floor():
    aggregator = AssuranceAggregator()
    # CRITICAL with confidence 0.55 -> r_i = 0.55. Veto fires!
    f = make_finding(
        threat_id="MT-3",
        category="MODEL_INTEGRITY",
        severity=SeverityLevel.CRITICAL,
        confidence=0.55,
        recommended_disposition=Disposition.REVIEW,
    )

    verdict = aggregator.aggregate(
        asset_id=f.asset_id,
        session_id=f.session_id,
        findings=[f],
        unsupported_checks=[],
    )

    assert verdict.composite_risk_score >= 0.70
    assert verdict.disposition == Disposition.QUARANTINE


# =====================================================================
# L. Missing Evidence / Incomplete Checks
# =====================================================================
def test_category_l_missing_evidence():
    aggregator = AssuranceAggregator()
    verdict = aggregator.aggregate(
        asset_id=uuid4(),
        session_id=uuid4(),
        findings=[],
        unsupported_checks=["DS-3", "DT-5"],
    )

    assert "DS-3" in verdict.unsupported_checks
    assert "DT-5" in verdict.unsupported_checks
    # Missing evidence must NOT produce ACCEPT
    assert verdict.disposition == Disposition.REVIEW
    assert "INCOMPLETE" in verdict.summary


# =====================================================================
# M. Insufficient Evidence from Skipped Analyses
# =====================================================================
def test_category_m_insufficient_evidence():
    aggregator = AssuranceAggregator()
    skipped = [
        {"analysis_id": "DS-1", "reason": "Sample size N < 15 insufficient"},
        {"analysis_id": "DS-2", "reason": "Class metadata unavailable"},
    ]

    verdict = aggregator.aggregate(
        asset_id=uuid4(),
        session_id=uuid4(),
        findings=[],
        skipped_analyses=skipped,
    )

    assert "DS-1" in verdict.unsupported_checks
    assert "DS-2" in verdict.unsupported_checks
    assert verdict.disposition == Disposition.REVIEW


# =====================================================================
# N. Unsupported Checks Dedup and Consolidation
# =====================================================================
def test_category_n_unsupported_checks_consolidation():
    aggregator = AssuranceAggregator()
    unsupported = ["DT-1", "DT-2", "DT-1"]
    skipped = [{"analysis_id": "DT-2"}, {"analysis_id": "DT-3"}]

    cleaned = aggregator.process_unsupported_checks(unsupported, skipped)
    assert cleaned == ["DT-1", "DT-2", "DT-3"]


# =====================================================================
# O. Incomplete Coverage Cannot ACCEPT
# =====================================================================
def test_category_o_incomplete_coverage_cannot_accept():
    aggregator = AssuranceAggregator()
    # Zero findings (clean), but 1 unsupported check
    verdict = aggregator.aggregate(
        asset_id=uuid4(),
        session_id=uuid4(),
        findings=[],
        unsupported_checks=["MT-1"],
    )

    assert verdict.disposition != Disposition.ACCEPT
    assert verdict.disposition == Disposition.REVIEW


# =====================================================================
# P. Duplicate Evidence Handling
# =====================================================================
def test_category_p_duplicate_evidence_handling():
    aggregator = AssuranceAggregator()
    f = make_finding(threat_id="DT-1", category="DATA_INTEGRITY", severity=SeverityLevel.MEDIUM, confidence=0.70)

    # Pass identical finding twice
    verdict_single = aggregator.aggregate(f.asset_id, f.session_id, [f])
    verdict_double = aggregator.aggregate(f.asset_id, f.session_id, [f, f])

    assert verdict_single.composite_risk_score == verdict_double.composite_risk_score
    assert verdict_single.disposition == verdict_double.disposition
    assert len(verdict_double.contributing_finding_ids) == 1


# =====================================================================
# Q. Conflicting Evidence
# =====================================================================
def test_category_q_conflicting_evidence():
    aggregator = AssuranceAggregator()
    # 1 critical model backdoor + 10 benign low data integrity findings
    crit_model = make_finding(
        threat_id="MT-3",
        category="MODEL_INTEGRITY",
        severity=SeverityLevel.CRITICAL,
        confidence=0.95,
        recommended_disposition=Disposition.QUARANTINE,
    )
    benign_data = [
        make_finding(threat_id=f"DT-{i%5+1}", category="DATA_INTEGRITY", severity=SeverityLevel.INFORMATIONAL, confidence=0.0)
        for i in range(10)
    ]

    verdict = aggregator.aggregate(
        asset_id=crit_model.asset_id,
        session_id=crit_model.session_id,
        findings=[crit_model] + benign_data,
        unsupported_checks=[],
    )

    # Critical veto MUST NOT be outvoted by 10 benign findings
    assert verdict.disposition == Disposition.QUARANTINE
    assert verdict.composite_risk_score >= 0.70


# =====================================================================
# R. Invalid Confidence Validation
# =====================================================================
def test_category_r_invalid_confidence():
    # Negative confidence
    with pytest.raises(Exception):
        make_finding(confidence=-0.1)

    # Confidence > 1.0
    with pytest.raises(Exception):
        make_finding(confidence=1.2)


# =====================================================================
# S. NaN / Inf Sanitization
# =====================================================================
def test_category_s_nan_inf_validation():
    aggregator = AssuranceAggregator()
    f = make_finding(confidence=0.5)

    # Manually bypass pydantic validator to test aggregator's internal defense
    f_dict = f.model_dump()
    f_dict["confidence"] = float("nan")

    # validate_finding_for_assurance must reject NaN
    with pytest.raises(SchemaValidationError, match="non-finite"):
        invalid_f = Finding.model_construct(**f_dict)
        validate_finding_for_assurance(invalid_f)

    f_dict["confidence"] = float("inf")
    with pytest.raises(SchemaValidationError, match="non-finite"):
        invalid_f = Finding.model_construct(**f_dict)
        validate_finding_for_assurance(invalid_f)


# =====================================================================
# T. Deterministic Repeated Aggregation
# =====================================================================
def test_category_t_deterministic_repeated_aggregation():
    aggregator = AssuranceAggregator()
    asset_id = uuid4()
    session_id = uuid4()
    f1 = make_finding(threat_id="DT-2", category="DATA_INTEGRITY", severity=SeverityLevel.HIGH, confidence=0.75, asset_id=asset_id, session_id=session_id)
    f2 = make_finding(threat_id="MT-1", category="MODEL_INTEGRITY", severity=SeverityLevel.MEDIUM, confidence=0.60, asset_id=asset_id, session_id=session_id)

    runs = [
        aggregator.aggregate(asset_id, session_id, [f1, f2], unsupported_checks=["DS-4"])
        for _ in range(50)
    ]

    for r in runs[1:]:
        assert r.composite_risk_score == runs[0].composite_risk_score
        assert r.disposition == runs[0].disposition
        assert r.contributing_finding_ids == runs[0].contributing_finding_ids
        assert r.unsupported_checks == runs[0].unsupported_checks
        assert r.summary == runs[0].summary


# =====================================================================
# U. Schema Validation
# =====================================================================
def test_category_u_schema_validation():
    aggregator = AssuranceAggregator()
    verdict = aggregator.aggregate(uuid4(), uuid4(), [])

    # Verify Pydantic serialization round-trip
    canonical_json = verdict.to_canonical_json()
    reconstructed = AssuranceVerdict.model_validate_json(canonical_json)
    assert reconstructed.verdict_id == verdict.verdict_id
    assert reconstructed.composite_risk_score == verdict.composite_risk_score
    assert reconstructed.schema_version == "1.0"


# =====================================================================
# V. Audit Logging & DB Integration
# =====================================================================
def test_category_v_audit_and_db_integration(db_manager, audit_logger):
    orchestrator = AssuranceOrchestrator(
        db_manager=db_manager,
        audit_logger=audit_logger,
    )

    asset_id = uuid4()
    session_id = uuid4()

    from cvif.core.enums import AssetType
    from cvif.core.schemas import AssetRegistration, HashManifest

    asset = AssetRegistration(
        asset_id=asset_id,
        asset_type=AssetType.MODEL,
        format="onnx",
        file_paths=["model.onnx"],
        hash_manifest=HashManifest(entries=[]),
        total_size_bytes=1024,
    )
    db_manager.save_asset(asset)

    f = make_finding(threat_id="IT-1", category="INFERENCE_PROVENANCE", severity=SeverityLevel.CRITICAL, confidence=0.99, asset_id=asset_id, session_id=session_id)

    session = AnalysisSession(
        session_id=session_id,
        asset_id=asset_id,
        findings=[f],
        skipped_analyses=[{"analysis_id": "DS-1", "reason": "No evaluation set"}],
    )

    verdict = orchestrator.evaluate_session(session)

    # 1. Attached to session
    assert session.verdict == verdict
    assert verdict.disposition == Disposition.QUARANTINE

    # 2. Persisted to SQLite
    stored_verdict = db_manager.get_verdict_for_session(session_id)
    assert stored_verdict is not None
    assert stored_verdict.verdict_id == verdict.verdict_id
    assert stored_verdict.disposition == Disposition.QUARANTINE

    # 3. Audit trail contains VERDICT_ISSUED and DISPOSITION_APPLIED
    chain_res = audit_logger.verify_chain()
    assert chain_res.is_valid is True
    assert chain_res.total_events >= 2


# =====================================================================
# W. Air-Gap Offline Execution
# =====================================================================
def test_category_w_air_gap_offline(air_gap_enforcer):
    aggregator = AssuranceAggregator()
    f = make_finding(threat_id="DT-3", category="DATA_INTEGRITY", severity=SeverityLevel.LOW, confidence=0.50)
    verdict = aggregator.aggregate(uuid4(), uuid4(), [f])
    assert verdict is not None


# =====================================================================
# ANTI-STUB TESTS (1 through 9)
# =====================================================================
def test_anti_stub_1_confidence_sensitivity():
    aggregator = AssuranceAggregator()
    f_low_conf = make_finding(threat_id="DT-4", category="DATA_INTEGRITY", severity=SeverityLevel.HIGH, confidence=0.20)
    f_high_conf = make_finding(threat_id="DT-4", category="DATA_INTEGRITY", severity=SeverityLevel.HIGH, confidence=0.90)

    v1 = aggregator.aggregate(uuid4(), uuid4(), [f_low_conf])
    v2 = aggregator.aggregate(uuid4(), uuid4(), [f_high_conf])

    assert v1.composite_risk_score != v2.composite_risk_score
    assert v1.composite_risk_score < v2.composite_risk_score


def test_anti_stub_2_severity_weight_sensitivity():
    aggregator = AssuranceAggregator()
    f_low_sev = make_finding(threat_id="MT-2", category="MODEL_INTEGRITY", severity=SeverityLevel.LOW, confidence=0.80)
    f_high_sev = make_finding(threat_id="MT-2", category="MODEL_INTEGRITY", severity=SeverityLevel.HIGH, confidence=0.80)

    v1 = aggregator.aggregate(uuid4(), uuid4(), [f_low_sev])
    v2 = aggregator.aggregate(uuid4(), uuid4(), [f_high_sev])

    assert v1.composite_risk_score < v2.composite_risk_score


def test_anti_stub_3_adding_finding_escalates_risk():
    aggregator = AssuranceAggregator()
    f1 = make_finding(threat_id="IT-3", category="INFERENCE_PROVENANCE", severity=SeverityLevel.MEDIUM, confidence=0.50)
    f2 = make_finding(threat_id="IT-5", category="INFERENCE_PROVENANCE", severity=SeverityLevel.MEDIUM, confidence=0.50)

    dim1, _ = aggregator.compute_dimensional_scores([f1])
    dim2, _ = aggregator.compute_dimensional_scores([f1, f2])

    assert dim1["inference_provenance"] < dim2["inference_provenance"]


def test_anti_stub_4_removing_finding_changes_result():
    aggregator = AssuranceAggregator()
    f1 = make_finding(threat_id="DS-1", category="DISTRIBUTION_SHIFT", severity=SeverityLevel.HIGH, confidence=0.80)
    f2 = make_finding(threat_id="DS-2", category="DISTRIBUTION_SHIFT", severity=SeverityLevel.MEDIUM, confidence=0.60)

    v_all = aggregator.aggregate(uuid4(), uuid4(), [f1, f2])
    v_sub = aggregator.aggregate(uuid4(), uuid4(), [f2])

    assert v_all.composite_risk_score > v_sub.composite_risk_score


def test_anti_stub_5_critical_veto_cannot_be_diluted():
    aggregator = AssuranceAggregator()
    crit = make_finding(threat_id="MT-3", category="MODEL_INTEGRITY", severity=SeverityLevel.CRITICAL, confidence=0.90)
    many_benign = [
        make_finding(threat_id="DT-1", category="DATA_INTEGRITY", severity=SeverityLevel.LOW, confidence=0.01)
        for _ in range(50)
    ]

    verdict = aggregator.aggregate(uuid4(), uuid4(), [crit] + many_benign)
    assert verdict.disposition == Disposition.QUARANTINE
    assert verdict.composite_risk_score >= 0.70


def test_anti_stub_6_missing_evidence_does_not_become_zero_risk():
    aggregator = AssuranceAggregator()
    verdict = aggregator.aggregate(uuid4(), uuid4(), [], unsupported_checks=["MT-3"])
    assert verdict.disposition == Disposition.REVIEW
    assert "INCOMPLETE" in verdict.summary


def test_anti_stub_7_incomplete_verification_cannot_accept():
    aggregator = AssuranceAggregator()
    verdict = aggregator.aggregate(uuid4(), uuid4(), [], unsupported_checks=["ALL_CHECKS"])
    assert verdict.disposition != Disposition.ACCEPT


def test_anti_stub_8_invalid_severity_rejected():
    with pytest.raises(Exception):
        make_finding(severity="SUPER_CRITICAL")


def test_anti_stub_9_identical_inputs_identical_canonical_output():
    aggregator = AssuranceAggregator()
    aid = uuid4()
    sid = uuid4()
    f = make_finding(threat_id="DT-1", category="DATA_INTEGRITY", severity=SeverityLevel.LOW, confidence=0.30, asset_id=aid, session_id=sid)

    v1 = aggregator.aggregate(aid, sid, [f])
    v2 = aggregator.aggregate(aid, sid, [f])

    assert v1.composite_risk_score == v2.composite_risk_score
    assert v1.disposition == v2.disposition
    assert v1.unsupported_checks == v2.unsupported_checks


# =====================================================================
# PERFORMANCE BENCHMARK (Section 22)
# =====================================================================
def test_performance_benchmarks():
    aggregator = AssuranceAggregator()
    aid = uuid4()
    sid = uuid4()

    counts = [10, 100, 1000, 5000]
    timings = {}

    for count in counts:
        findings = [
            make_finding(
                threat_id=f"DT-{i % 6 + 1}",
                category="DATA_INTEGRITY" if i % 2 == 0 else "MODEL_INTEGRITY",
                severity=SeverityLevel.MEDIUM if i % 3 == 0 else SeverityLevel.LOW,
                confidence=0.50,
                asset_id=aid,
                session_id=sid,
            )
            for i in range(count)
        ]

        t0 = time.perf_counter()
        verdict = aggregator.aggregate(aid, sid, findings)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        timings[count] = elapsed_ms

        assert verdict is not None
        assert isinstance(verdict.composite_risk_score, float)

    # 1,000 findings must aggregate in < 100 ms
    assert timings[1000] < 100.0, f"1,000 findings took {timings[1000]:.2f} ms (expected < 100 ms)"


# =====================================================================
# COVERAGE SEMANTICS REGRESSION TESTS (Sections 7.A through 7.F)
# =====================================================================
def test_regression_a_supported_executed_check_with_finding():
    """A. Supported executed check with finding -> contributes risk, NOT unsupported."""
    aggregator = AssuranceAggregator()
    aid = uuid4()
    sid = uuid4()
    f = make_finding(
        threat_id="DT-5",
        category="DATA_INTEGRITY",
        severity=SeverityLevel.MEDIUM,
        confidence=0.604,
        recommended_disposition=Disposition.REVIEW,
        asset_id=aid,
        session_id=sid,
    )

    # Even if DT-5 erroneously appeared in skipped_analyses due to an execution/logging glitch,
    # because it executed and produced a verified finding, it MUST NOT be labeled unsupported.
    verdict = aggregator.aggregate(
        asset_id=aid,
        session_id=sid,
        findings=[f],
        skipped_analyses=[{"analysis_id": "DT-5", "reason": "DB error"}],
        executed_analyses=["DT-5"],
    )

    assert verdict.composite_risk_score > 0.0
    assert f.finding_id in verdict.contributing_finding_ids
    assert "DT-5" not in verdict.unsupported_checks
    assert verdict.unsupported_checks == []


def test_regression_b_supported_executed_check_no_finding():
    """B. Supported executed check with no finding -> covered, no risk contribution."""
    aggregator = AssuranceAggregator()
    aid = uuid4()
    sid = uuid4()

    # Checks DT-1 and DT-4 executed cleanly with no findings
    verdict = aggregator.aggregate(
        asset_id=aid,
        session_id=sid,
        findings=[],
        unsupported_checks=[],
        executed_analyses=["DT-1", "DT-4"],
    )

    assert verdict.composite_risk_score == 0.0
    assert verdict.contributing_finding_ids == []
    assert verdict.unsupported_checks == []
    assert verdict.disposition == Disposition.ACCEPT
    assert "COMPLETE" in verdict.summary


def test_regression_c_unsupported_unperformed_check():
    """C. Unsupported/unperformed check -> appears in coverage gap, cannot fabricate risk."""
    aggregator = AssuranceAggregator()
    aid = uuid4()
    sid = uuid4()

    # Check DT-2 was skipped due to insufficient samples/classes
    verdict = aggregator.aggregate(
        asset_id=aid,
        session_id=sid,
        findings=[],
        skipped_analyses=[{"analysis_id": "DT-2", "reason": "Insufficient samples or classes"}],
    )

    assert "DT-2" in verdict.unsupported_checks
    assert verdict.composite_risk_score == 0.0
    assert verdict.contributing_finding_ids == []
    # Incomplete coverage forces REVIEW and prevents ACCEPT
    assert verdict.disposition == Disposition.REVIEW
    assert "INCOMPLETE" in verdict.summary
    assert "Asset cannot receive ACCEPT disposition" in verdict.summary


def test_regression_d_partial_session_coverage():
    """D. Partial session with executed threats + skipped checks -> REVIEW / incomplete coverage without overlap."""
    aggregator = AssuranceAggregator()
    aid = uuid4()
    sid = uuid4()

    f_ood = make_finding(threat_id="DT-5", category="DATA_INTEGRITY", severity=SeverityLevel.MEDIUM, confidence=0.604, asset_id=aid, session_id=sid)
    f_contrib = make_finding(threat_id="DT-6", category="DATA_INTEGRITY", severity=SeverityLevel.MEDIUM, confidence=0.85, asset_id=aid, session_id=sid)

    # Replicate exact condition from real session 92c97d38:
    # DT-1 and DT-4 passed cleanly; DT-5 and DT-6 executed with findings; DT-2 and DT-3 skipped;
    # DT-5 and DT-6 had DB errors that caused them to appear in skipped_analyses.
    verdict = aggregator.aggregate(
        asset_id=aid,
        session_id=sid,
        findings=[f_ood, f_contrib],
        executed_analyses=["DT-4", "DT-1", "DT-5", "DT-6"],
        skipped_analyses=[
            {"analysis_id": "DT-2", "reason": "Insufficient samples or classes"},
            {"analysis_id": "DT-3", "reason": "Insufficient samples or classes"},
            {"analysis_id": "DT-5", "reason": "Execution error: Database transaction failed"},
            {"analysis_id": "DT-6", "reason": "Database transaction failed"},
        ],
    )

    # 1. Contributing findings contain DT-5 and DT-6
    assert len(verdict.contributing_finding_ids) == 2
    assert f_ood.finding_id in verdict.contributing_finding_ids
    assert f_contrib.finding_id in verdict.contributing_finding_ids

    # 2. Unsupported checks contain ONLY DT-2 and DT-3 (NO DT-5 or DT-6!)
    assert verdict.unsupported_checks == ["DT-2", "DT-3"]
    assert "DT-5" not in verdict.unsupported_checks
    assert "DT-6" not in verdict.unsupported_checks

    # 3. Overall disposition is REVIEW due to both risk score and incomplete coverage
    assert verdict.disposition == Disposition.REVIEW
    assert "Verification Coverage INCOMPLETE: 2 check(s) unperformed/skipped: ['DT-2', 'DT-3']" in verdict.summary


def test_regression_e_critical_finding_weakest_link_veto():
    """E. Critical finding -> Weakest-Link veto forces QUARANTINE regardless of unsupported checks."""
    aggregator = AssuranceAggregator()
    aid = uuid4()
    sid = uuid4()

    crit = make_finding(
        threat_id="MT-3",
        category="MODEL_INTEGRITY",
        severity=SeverityLevel.CRITICAL,
        confidence=0.90,
        asset_id=aid,
        session_id=sid,
    )

    # Even with unsupported checks present, a CRITICAL veto must trigger QUARANTINE
    verdict = aggregator.aggregate(
        asset_id=aid,
        session_id=sid,
        findings=[crit],
        unsupported_checks=["DT-2", "DT-3"],
    )

    assert verdict.disposition == Disposition.QUARANTINE
    assert verdict.composite_risk_score >= 0.70
    assert "CRITICAL VETO TRIGGERED" in verdict.summary
    assert "DT-2" in verdict.unsupported_checks
    assert "DT-3" in verdict.unsupported_checks


def test_regression_f_no_evidence_cannot_accept():
    """F. No evidence -> must not be interpreted as ACCEPT."""
    aggregator = AssuranceAggregator()
    aid = uuid4()
    sid = uuid4()

    # Asset where all checks were unsupported / unperformed
    verdict = aggregator.aggregate(
        asset_id=aid,
        session_id=sid,
        findings=[],
        unsupported_checks=["DT-1", "DT-2", "DT-3", "DT-4", "DT-5", "DT-6"],
    )

    assert verdict.disposition != Disposition.ACCEPT
    assert verdict.disposition == Disposition.REVIEW
    assert "INCOMPLETE" in verdict.summary
    assert len(verdict.unsupported_checks) == 6

