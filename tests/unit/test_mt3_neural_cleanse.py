"""Unit tests for Phase 4 Revision A: Genuine MT-3 Neural Cleanse Implementation."""

import math
from pathlib import Path
from typing import Any, Dict, List, Tuple
import pytest

from cvif.analysis.model_integrity.backdoor import BackdoorBehaviorCheck
from cvif.core.enums import Disposition, EvidenceType, ModelAccessLevel, ModelTask, SeverityLevel
from cvif.core.exceptions import AccessDeniedError, InvalidModelError
from cvif.model.adapter import MockModelAdapter, ModelAdapter
from cvif.model.adapters.onnx_adapter import ONNXAdapter
from cvif.model.adapters.pytorch_adapter import PyTorchAdapter
from cvif.model.adapters.torchscript_adapter import TorchScriptAdapter
from cvif.model.battery import ReferenceBatteryBuilder


# =====================================================================
# Test A — Differentiable Toy Model
# =====================================================================


def test_a_differentiable_toy_model_optimization():
    """Verify that a genuine differentiable model exposes real gradients, updates parameters via Adam,
    reduces loss, and increases target class confidence.
    """
    model = MockModelAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
    )
    assert model.is_differentiable() is True
    assert model.get_gradient_capability() == "ANALYTICAL_GRADIENT"

    # Verify gradients exist and are non-trivial
    initial_x = [0.2] * 16
    target_class = 1
    init_loss, init_conf, g_x = model.compute_input_gradients(initial_x, target_class)

    assert isinstance(init_loss, float)
    assert init_loss > 0.0
    assert isinstance(init_conf, float)
    assert len(g_x) == 16
    assert any(abs(g) > 1e-5 for g in g_x), "Input gradient vector must contain non-zero gradients"

    # Perform actual optimization loop on mask M and pattern P
    M = [0.01] * 16
    P = [0.5] * 16
    lr = 0.1
    lambda_reg = 0.02

    m_M, v_M = [0.0] * 16, [0.0] * 16
    m_P, v_P = [0.0] * 16, [0.0] * 16

    losses = []
    confs = []

    for it in range(30):
        x_prime = [(1.0 - M[j]) * initial_x[j] + M[j] * P[j] for j in range(16)]
        loss_ce, conf, g_x_cur = model.compute_input_gradients(x_prime, target_class)
        loss_reg = lambda_reg * sum(abs(m) for m in M)
        total_loss = loss_ce + loss_reg
        losses.append(total_loss)
        confs.append(conf)

        grad_M = [
            g_x_cur[j] * (P[j] - initial_x[j]) + (lambda_reg if M[j] >= 0 else -lambda_reg)
            for j in range(16)
        ]
        grad_P = [g_x_cur[j] * M[j] for j in range(16)]

        for j in range(16):
            m_M[j] = 0.9 * m_M[j] + 0.1 * grad_M[j]
            v_M[j] = 0.999 * v_M[j] + 0.001 * (grad_M[j] ** 2)
            m_hat_m = m_M[j] / (1.0 - (0.9 ** (it + 1)))
            v_hat_m = v_M[j] / (1.0 - (0.999 ** (it + 1)))
            M[j] = max(0.0, min(1.0, M[j] - lr * m_hat_m / (math.sqrt(v_hat_m) + 1e-8)))

            m_P[j] = 0.9 * m_P[j] + 0.1 * grad_P[j]
            v_P[j] = 0.999 * v_P[j] + 0.001 * (grad_P[j] ** 2)
            m_hat_p = m_P[j] / (1.0 - (0.9 ** (it + 1)))
            v_hat_p = v_P[j] / (1.0 - (0.999 ** (it + 1)))
            P[j] = max(0.0, min(1.0, P[j] - lr * m_hat_p / (math.sqrt(v_hat_p) + 1e-8)))

    # Verifications
    # 1. Loss changed and decreased across iterations
    assert losses[-1] < losses[0], f"Optimization must reduce objective: initial={losses[0]}, final={losses[-1]}"
    # 2. Final mask differs from initialization
    assert M != [0.01] * 16, "Mask parameters must be updated during optimization"
    # 3. Final pattern differs from initialization
    assert P != [0.5] * 16, "Pattern parameters must be updated during optimization"
    # 4. Target confidence increased
    assert confs[-1] > confs[0], f"Target confidence must increase: initial={confs[0]}, final={confs[-1]}"


# =====================================================================
# Test B — No Mock Metadata
# =====================================================================


def test_b_no_mock_metadata():
    """Verify MT-3 functions and detects backdoor even when 'backdoor_target_class' does NOT exist on the model."""
    model = MockModelAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
    )
    # Physically trojan the weight matrix for class 2 (aerial_drone)
    model.inject_backdoor_trojan(target_class=2, feature_indices=[0, 1], weight=8.0)

    # Completely delete the mock attribute
    if hasattr(model, "backdoor_target_class"):
        delattr(model, "backdoor_target_class")
    assert not hasattr(model, "backdoor_target_class")

    check = BackdoorBehaviorCheck()
    findings = check.run(model)

    assert len(findings) == 1
    f = findings[0]
    assert f.threat_id == "MT-3"
    assert f.severity == SeverityLevel.HIGH
    assert f.recommended_disposition == Disposition.QUARANTINE
    assert "aerial_drone" in f.title


# =====================================================================
# Test C — Mock Metadata Cannot Influence Result
# =====================================================================


def test_c_mock_metadata_cannot_influence_result():
    """Verify that misleading or fake 'backdoor_target_class' attributes cannot alter MT-3 results."""
    check = BackdoorBehaviorCheck()

    # Case 1: Model has genuine trojan on class 1 (civilian_car), but mock attribute claims class 99
    m_trojan = MockModelAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
    )
    m_trojan.inject_backdoor_trojan(target_class=1, feature_indices=[0, 1], weight=8.0)
    m_trojan.backdoor_target_class = 99  # Misleading test-only attribute

    findings = check.run(m_trojan)
    assert len(findings) == 1
    # Must identify class 1 (civilian_car), NOT class 99
    assert "civilian_car" in findings[0].title
    assert "99" not in findings[0].title

    # Case 2: Clean model with balanced weights, but misleading backdoor_target_class = 1
    m_clean = MockModelAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
    )
    m_clean.backdoor_target_class = 1  # Fake attribute on a clean model

    findings_clean = check.run(m_clean)
    # Detector must rely on genuine weights, discover no anomaly, and emit ZERO backdoor findings
    assert len(findings_clean) == 0


# =====================================================================
# Test D — Unsupported Model
# =====================================================================


def test_d_unsupported_model(temp_dir: Path):
    """Verify that non-differentiable adapters return explicit UNSUPPORTED_GRADIENT_ACCESS findings
    rather than fabricating measurements.
    """
    check = BackdoorBehaviorCheck()

    # 1. ONNX adapter (grey-box runtime without autograd)
    onnx_file = temp_dir / "model.onnx"
    onnx_file.write_bytes(b"dummy_onnx_content")
    oa = ONNXAdapter(model_path=onnx_file, task=ModelTask.CLASSIFICATION)
    assert oa.is_differentiable() is False

    findings_oa = check.run(oa)
    assert len(findings_oa) == 1
    assert findings_oa[0].severity == SeverityLevel.INFORMATIONAL
    assert "Unsupported" in findings_oa[0].title
    assert "UNSUPPORTED_GRADIENT_ACCESS" in findings_oa[0].description

    # 2. TorchScript adapter
    ts_file = temp_dir / "model.pt"
    ts_file.write_bytes(b"dummy_ts_content")
    ta = TorchScriptAdapter(model_path=ts_file, task=ModelTask.CLASSIFICATION)
    assert ta.is_differentiable() is False

    findings_ta = check.run(ta)
    assert len(findings_ta) == 1
    assert findings_ta[0].severity == SeverityLevel.INFORMATIONAL
    assert "Unsupported" in findings_ta[0].title
    assert "UNSUPPORTED_GRADIENT_ACCESS" in findings_ta[0].description

    # 3. Black-box mock adapter
    bb = MockModelAdapter(task=ModelTask.CLASSIFICATION, access_level=ModelAccessLevel.BLACK_BOX)
    assert bb.is_differentiable() is False

    findings_bb = check.run(bb)
    assert len(findings_bb) == 1
    assert findings_bb[0].severity == SeverityLevel.INFORMATIONAL
    assert "Unsupported" in findings_bb[0].title
    assert "UNSUPPORTED_GRADIENT_ACCESS" in findings_bb[0].description


# =====================================================================
# Test E — MAD Robustness
# =====================================================================


def test_e_mad_robustness_edge_cases():
    """Test MAD calculation across edge cases: normal, zero MAD, insufficient classes, and NaN/Inf."""
    check = BackdoorBehaviorCheck()
    battery = ReferenceBatteryBuilder.create_synthetic_battery(ModelTask.CLASSIFICATION)

    # 1. Insufficient classes (< 3 classes)
    m_binary = MockModelAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
        class_names=["tank", "drone"],
    )
    findings_bin = check.run(m_binary, battery=battery)
    assert len(findings_bin) == 1
    assert findings_bin[0].severity == SeverityLevel.INFORMATIONAL
    assert "Insufficient Evidence" in findings_bin[0].title

    # 2. Direct unit test of _neural_cleanse_analysis MAD calculation logic
    # Mock adapter with perfectly identical norms (zero MAD)
    class ZeroMADAdapter(MockModelAdapter):
        def compute_input_gradients(self, input_data: Any, target_class: int) -> Tuple[float, float, List[float]]:
            # Return zero gradients so mask never updates from initial value
            return 0.5, 0.5, [0.0] * self._diff_dim

    m_zero_mad = ZeroMADAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
    )
    res_zero_mad = check._neural_cleanse_analysis(m_zero_mad, battery, max_iterations=10)
    assert res_zero_mad["status"] == "SUCCESS"
    assert res_zero_mad["mad"] == 0.0
    assert res_zero_mad["anomaly_index"] == 0.0

    # 3. NaN/Inf handling in statistical filter
    class NanGradAdapter(MockModelAdapter):
        def compute_input_gradients(self, input_data: Any, target_class: int) -> Tuple[float, float, List[float]]:
            if target_class == 0:
                return float("nan"), float("nan"), [float("nan")] * self._diff_dim
            return 0.5, 0.5, [0.1] * self._diff_dim

    m_nan = NanGradAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
        class_names=["cls0", "cls1", "cls2"],  # 3 classes, 1 produces NaN -> 2 valid remaining -> <3
    )
    res_nan = check._neural_cleanse_analysis(m_nan, battery, max_iterations=5)
    assert res_nan["status"] == "INSUFFICIENT_EVIDENCE"


# =====================================================================
# Test F — Security Boundary
# =====================================================================


def test_f_security_boundary_preservation(temp_dir: Path):
    """Verify that MT-3 and differentiable models cannot bypass the pre-flight safety scanner."""
    # Attempting to load an unsafe model containing malicious/suspicious payload
    unsafe_model_path = temp_dir / "exploit.pt"
    # Construct pickle payload with forbidden reducer
    unsafe_model_path.write_bytes(b"cposix\nsystem\np0\n(S'id'\np1\ntp2\nRp3\n.")

    adapter = PyTorchAdapter(model_path=unsafe_model_path)
    with pytest.raises(InvalidModelError) as exc_info:
        adapter.load()
    assert "safety check failed" in str(exc_info.value).lower()

    # Differentiable gradient access must be denied for BLACK_BOX models
    bb_model = MockModelAdapter(access_level=ModelAccessLevel.BLACK_BOX)
    with pytest.raises(AccessDeniedError):
        bb_model.compute_input_gradients([0.1] * 16, 0)
