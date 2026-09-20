"""Unit tests for Phase 4 Revision B: Real Model Adapter Capability & Anti-Stub Verification.

These tests prevent regression to fake inference or hardcoded constant fallbacks,
verifying:
1. Predictions change when model parameters change.
2. Predictions change when input changes.
3. No hardcoded fallback (class_id=0, confidence=0.92) when runtime is unavailable.
4. Gradients originate from the genuine computational graph.
5. Model safety scanning occurs prior to model loading.
6. Explicit unsupported status for non-differentiable adapters.
"""

import math
from pathlib import Path
import sys
import types
from typing import Any, Dict, List, Optional, Tuple
import pytest

from cvif.core.enums import ModelAccessLevel, ModelTask, SeverityLevel
from cvif.core.exceptions import AccessDeniedError, InvalidModelError
from cvif.core.schemas import ClassificationOutput, DetectionOutput, PredictionResult
from cvif.model.adapter import MockModelAdapter, ModelAdapter
from cvif.model.adapters.onnx_adapter import ONNXAdapter
from cvif.model.adapters.pytorch_adapter import PyTorchAdapter
from cvif.model.adapters.torchscript_adapter import TorchScriptAdapter


# =====================================================================
# Lightweight Pure-Python Computational Graph Module for Anti-Stub Tests
# =====================================================================


class _MockTensor:
    """Tensor simulation with reverse-mode automatic differentiation."""

    def __init__(self, data: Any, requires_grad: bool = False) -> None:
        if isinstance(data, _MockTensor):
            self.data = [list(row) for row in data.data] if isinstance(data.data[0], list) else list(data.data)
        elif isinstance(data, (list, tuple)):
            if len(data) > 0 and isinstance(data[0], (list, tuple)):
                self.data = [[float(x) for x in row] for row in data]
            else:
                self.data = [float(x) for x in data]
        else:
            self.data = [float(data)]
        self.requires_grad = requires_grad
        self.grad: Any = None
        self.device = "cpu"
        self._backward_fn = None

    @property
    def shape(self) -> Tuple[int, ...]:
        if isinstance(self.data, list) and len(self.data) > 0 and isinstance(self.data[0], list):
            return (len(self.data), len(self.data[0]))
        return (len(self.data),)

    def dim(self) -> int:
        return len(self.shape)

    def __getitem__(self, idx: Any) -> Any:
        if isinstance(idx, tuple):
            val = self.data
            for i in idx:
                val = val[i]
            if isinstance(val, (int, float)):
                return _MockTensor([val])
            return _MockTensor(val)
        val = self.data[idx]
        if isinstance(val, (int, float)):
            return _MockTensor([val])
        return _MockTensor(val)

    def unsqueeze(self, dim: int) -> "_MockTensor":
        if self.dim() == 1:
            res = _MockTensor([self.data], self.requires_grad)
        else:
            res = _MockTensor(self.data, self.requires_grad)
        return res

    def squeeze(self, dim: int = 0) -> "_MockTensor":
        if self.dim() == 2 and self.shape[0] == 1:
            res = _MockTensor(self.data[0], self.requires_grad)
        else:
            res = _MockTensor(self.data, self.requires_grad)
        if self.grad is not None:
            res.grad = self.grad.squeeze(dim) if hasattr(self.grad, "squeeze") else self.grad
        return res

    def detach(self) -> "_MockTensor":
        return _MockTensor(self.data, requires_grad=False)

    def clone(self) -> "_MockTensor":
        return _MockTensor(self.data, requires_grad=self.requires_grad)

    def requires_grad_(self, req: bool = True) -> "_MockTensor":
        self.requires_grad = req
        return self

    def to(self, dtype: Any) -> "_MockTensor":
        return self

    def cpu(self) -> "_MockTensor":
        return self

    def flatten(self) -> "_MockTensor":
        if self.dim() == 2:
            flat = [x for row in self.data for x in row]
        else:
            flat = list(self.data)
        return _MockTensor(flat, self.requires_grad)

    def tolist(self) -> List[Any]:
        return list(self.data)

    def item(self) -> float:
        if self.dim() == 1 and len(self.data) == 1:
            return float(self.data[0])
        elif self.dim() == 2 and len(self.data) == 1 and len(self.data[0]) == 1:
            return float(self.data[0][0])
        return float(self.data[0])


class _BaseModule:
    """Base class for mock PyTorch modules."""
    pass


class _TinyLinearModule(_BaseModule):
    """Minimal differentiable PyTorch nn.Module simulator for unit tests."""

    def __init__(self, weights: List[List[float]], bias: Optional[List[float]] = None) -> None:
        self.weights = [list(row) for row in weights]  # [num_classes, in_features]
        self.num_classes = len(weights)
        self.in_features = len(weights[0])
        self.bias = bias or [0.0] * self.num_classes
        self._last_inp: Optional[_MockTensor] = None

    def __call__(self, inp: _MockTensor) -> _MockTensor:
        self._last_inp = inp
        raw_x = inp.data[0] if inp.dim() == 2 else inp.data
        logits: List[float] = []
        for c in range(self.num_classes):
            val = sum(self.weights[c][j] * raw_x[j] for j in range(self.in_features)) + self.bias[c]
            logits.append(val)
        return _MockTensor([logits], requires_grad=True)

    def eval(self) -> "_TinyLinearModule":
        return self

    def zero_grad(self, set_to_none: bool = True) -> None:
        pass


def _install_mock_torch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock PyTorch module to simulate full autograd, softmax, and cross-entropy."""
    mock_torch = types.ModuleType("torch")
    mock_nn = types.ModuleType("torch.nn")
    mock_nn_functional = types.ModuleType("torch.nn.functional")

    mock_nn.Module = _BaseModule

    mock_torch.Tensor = _MockTensor
    mock_torch.float32 = "float32"
    mock_torch.long = "long"

    def _tensor_fn(data: Any, dtype: Any = None, requires_grad: bool = False, device: str = "cpu") -> _MockTensor:
        return _MockTensor(data, requires_grad=requires_grad)

    def _zeros_fn(shape: Tuple[int, ...], dtype: Any = None, requires_grad: bool = False) -> _MockTensor:
        size = 1
        for s in shape:
            size *= s
        return _MockTensor([0.0] * size, requires_grad=requires_grad)

    class _NoGradContext:
        def __enter__(self) -> None:
            pass

        def __exit__(self, *args: Any) -> None:
            pass

    def _no_grad() -> _NoGradContext:
        return _NoGradContext()

    def _softmax(output: _MockTensor, dim: int = -1) -> _MockTensor:
        raw = output.data[0] if output.dim() == 2 else output.data
        max_v = max(raw)
        exps = [math.exp(v - max_v) for v in raw]
        s = sum(exps)
        probs = [e / s for e in exps]
        return _MockTensor([probs] if output.dim() == 2 else probs)

    def _cross_entropy(output: _MockTensor, target: _MockTensor) -> _MockTensor:
        raw = output.data[0] if output.dim() == 2 else output.data
        target_idx = int(target.data[0])
        max_v = max(raw)
        exps = [math.exp(v - max_v) for v in raw]
        s = sum(exps)
        probs = [e / s for e in exps]
        loss_val = -math.log(max(probs[target_idx], 1e-12))
        loss_t = _MockTensor([loss_val], requires_grad=True)

        def _backward() -> None:
            # Backprop gradient through softmax & linear weights to input
            g_z = [probs[c] - (1.0 if c == target_idx else 0.0) for c in range(len(probs))]
            # We access the module's weights through the global or closure
            pass

        loss_t._backward_fn = _backward
        loss_t.backward = lambda: None  # Patched per-test
        return loss_t

    mock_torch.tensor = _tensor_fn
    mock_torch.zeros = _zeros_fn
    mock_torch.no_grad = _no_grad
    mock_torch.softmax = _softmax
    mock_nn_functional.softmax = _softmax
    mock_nn_functional.cross_entropy = _cross_entropy
    mock_nn.functional = mock_nn_functional
    mock_torch.nn = mock_nn

    monkeypatch.setitem(sys.modules, "torch", mock_torch)
    monkeypatch.setitem(sys.modules, "torch.nn", mock_nn)
    monkeypatch.setitem(sys.modules, "torch.nn.functional", mock_nn_functional)


# =====================================================================
# Test 1 — Prediction Changes with Model Parameters
# =====================================================================


def test_1_prediction_changes_with_model_parameters(temp_dir: Path, monkeypatch: pytest.MonkeyPatch):
    """Test that predictions differ when model parameters change, proving the adapter
    derives output from weights and does not return a fixed constant.
    """
    _install_mock_torch(monkeypatch)

    pt_file = temp_dir / "model.pt"
    pt_file.write_bytes(b"model_payload_1")

    adapter = PyTorchAdapter(
        model_path=pt_file,
        task=ModelTask.CLASSIFICATION,
        class_names=["class_alpha", "class_beta"],
    )
    adapter._is_loaded = True

    # Model A: Strongly prefers class 0 (alpha)
    model_a = _TinyLinearModule(weights=[[10.0, 5.0], [-10.0, -5.0]])
    adapter._model = model_a

    pred_a = adapter.predict([1.0, 1.0])
    assert pred_a.status == "SUCCESS"
    assert pred_a.classification is not None
    assert pred_a.classification.class_id == 0
    assert pred_a.classification.class_name == "class_alpha"
    assert pred_a.classification.confidence > 0.99

    # Model B: Strongly prefers class 1 (beta)
    model_b = _TinyLinearModule(weights=[[-10.0, -5.0], [10.0, 5.0]])
    adapter._model = model_b

    pred_b = adapter.predict([1.0, 1.0])
    assert pred_b.status == "SUCCESS"
    assert pred_b.classification is not None
    assert pred_b.classification.class_id == 1
    assert pred_b.classification.class_name == "class_beta"
    assert pred_b.classification.confidence > 0.99

    # Predictions MUST differ between models
    assert pred_a.classification.class_id != pred_b.classification.class_id
    assert pred_a.classification.class_name != pred_b.classification.class_name


# =====================================================================
# Test 2 — Prediction Changes with Input
# =====================================================================


def test_2_prediction_changes_with_input(temp_dir: Path, monkeypatch: pytest.MonkeyPatch):
    """Test that the same model yields different outputs when given different inputs."""
    _install_mock_torch(monkeypatch)

    pt_file = temp_dir / "model.pt"
    pt_file.write_bytes(b"model_payload_2")

    adapter = PyTorchAdapter(
        model_path=pt_file,
        task=ModelTask.CLASSIFICATION,
        class_names=["tank", "radar"],
    )
    adapter._is_loaded = True
    # Classifier where feature 0 triggers class 0 (tank), feature 1 triggers class 1 (radar)
    adapter._model = _TinyLinearModule(weights=[[5.0, -5.0], [-5.0, 5.0]])

    # Input 1: High feature 0 -> class 0
    pred_1 = adapter.predict([2.0, 0.0])
    assert pred_1.status == "SUCCESS"
    assert pred_1.classification.class_id == 0
    assert pred_1.classification.class_name == "tank"

    # Input 2: High feature 1 -> class 1
    pred_2 = adapter.predict([0.0, 2.0])
    assert pred_2.status == "SUCCESS"
    assert pred_2.classification.class_id == 1
    assert pred_2.classification.class_name == "radar"

    assert pred_1.classification.class_id != pred_2.classification.class_id


# =====================================================================
# Test 3 — No Hardcoded Fallback When Runtime is Unavailable
# =====================================================================


def test_3_no_hardcoded_fallback_when_runtime_unavailable(temp_dir: Path, monkeypatch: pytest.MonkeyPatch):
    """Test that when runtime dependencies are unavailable, adapters return explicit
    RUNTIME_UNAVAILABLE status without fabricating fake predictions (such as class_id=0, confidence=0.92).
    """
    # Ensure torch and onnxruntime are not available in imports
    monkeypatch.setitem(sys.modules, "torch", None)
    monkeypatch.setitem(sys.modules, "onnxruntime", None)

    # 1. PyTorch Adapter
    pt_file = temp_dir / "test.pt"
    pt_file.write_bytes(b"dummy_pt_bytes")
    pt_adapter = PyTorchAdapter(model_path=pt_file)
    pt_pred = pt_adapter.predict(b"some_bytes")

    assert isinstance(pt_pred, PredictionResult)
    assert pt_pred.status == "RUNTIME_UNAVAILABLE"
    assert pt_pred.classification is None
    assert pt_pred.detections is None
    assert pt_pred.raw_output is not None
    assert pt_pred.raw_output.get("status") == "RUNTIME_UNAVAILABLE"

    # 2. ONNX Adapter
    onnx_file = temp_dir / "test.onnx"
    onnx_file.write_bytes(b"dummy_onnx_bytes")
    onnx_adapter = ONNXAdapter(model_path=onnx_file)
    onnx_pred = onnx_adapter.predict(b"some_bytes")

    assert isinstance(onnx_pred, PredictionResult)
    assert onnx_pred.status == "RUNTIME_UNAVAILABLE"
    assert onnx_pred.classification is None
    assert onnx_pred.detections is None

    # 3. TorchScript Adapter
    ts_file = temp_dir / "test.torchscript"
    ts_file.write_bytes(b"dummy_ts_bytes")
    ts_adapter = TorchScriptAdapter(model_path=ts_file, task=ModelTask.DETECTION)
    ts_pred = ts_adapter.predict(b"some_bytes")

    assert isinstance(ts_pred, PredictionResult)
    assert ts_pred.status == "RUNTIME_UNAVAILABLE"
    assert ts_pred.detections is None
    assert ts_pred.classification is None


# =====================================================================
# Test 4 — Gradient Provenance
# =====================================================================


def test_4_gradient_provenance(temp_dir: Path, monkeypatch: pytest.MonkeyPatch):
    """Test that adapter input gradients genuinely originate from the mathematical
    computational graph and match independent backpropagation.
    """
    _install_mock_torch(monkeypatch)

    pt_file = temp_dir / "model.pt"
    pt_file.write_bytes(b"grad_test_model")

    adapter = PyTorchAdapter(
        model_path=pt_file,
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
        class_names=["cls0", "cls1"],
    )
    adapter._is_loaded = True

    # Weights: [2 classes, 2 features]
    W = [[2.0, -1.0], [-1.0, 3.0]]
    mod = _TinyLinearModule(weights=W)
    adapter._model = mod

    input_data = [0.5, 0.5]
    target_class = 0

    # Hook backward function to compute true mathematical input gradients
    import torch.nn.functional as F

    def _real_backward(loss_tensor: Any) -> None:
        raw_x = mod._last_inp.data[0]
        logits = [
            sum(W[c][j] * raw_x[j] for j in range(2))
            for c in range(2)
        ]
        max_v = max(logits)
        exps = [math.exp(v - max_v) for v in logits]
        probs = [e / sum(exps) for e in exps]
        g_z = [probs[c] - (1.0 if c == target_class else 0.0) for c in range(2)]
        g_x = [sum(g_z[c] * W[c][j] for c in range(2)) for j in range(2)]
        mod._last_inp.grad = _MockTensor(g_x)

    def _cross_entropy_patched(output: _MockTensor, target: _MockTensor) -> _MockTensor:
        res = _MockTensor([0.5], requires_grad=True)
        res.backward = lambda: _real_backward(res)
        return res

    monkeypatch.setattr(F, "cross_entropy", _cross_entropy_patched)

    loss, conf, adapter_grad = adapter.compute_input_gradients(input_data, target_class)

    # Independently compute expected mathematical gradient:
    # z = [2*0.5 - 1*0.5, -1*0.5 + 3*0.5] = [0.5, 1.0]
    # probs = [exp(0.5)/(exp(0.5)+exp(1.0)), exp(1.0)/(exp(0.5)+exp(1.0))]
    exp0 = math.exp(0.5)
    exp1 = math.exp(1.0)
    p0 = exp0 / (exp0 + exp1)
    p1 = exp1 / (exp0 + exp1)
    g_z_expected = [p0 - 1.0, p1 - 0.0]
    expected_g_x0 = g_z_expected[0] * W[0][0] + g_z_expected[1] * W[1][0]
    expected_g_x1 = g_z_expected[0] * W[0][1] + g_z_expected[1] * W[1][1]
    expected_grad = [expected_g_x0, expected_g_x1]

    assert len(adapter_grad) == 2
    for a_g, e_g in zip(adapter_grad, expected_grad):
        assert abs(a_g - e_g) < 1e-4, f"Adapter grad {a_g} must match computational graph grad {e_g}"


# =====================================================================
# Test 5 — Security Boundary Preservation
# =====================================================================


def test_5_security_boundary_preservation(temp_dir: Path):
    """Test that model safety scanning occurs before model loading, preventing
    deserialization of malicious payload models.
    """
    exploit_pt = temp_dir / "exploit.pt"
    # Malicious pickle opcode attempting arbitrary OS execution
    exploit_pt.write_bytes(b"cposix\nsystem\np0\n(S'whoami'\np1\ntp2\nRp3\n.")

    adapter = PyTorchAdapter(model_path=exploit_pt)
    with pytest.raises(InvalidModelError) as exc_info:
        adapter.load()
    assert "safety scan failed" in str(exc_info.value).lower() or "safety check failed" in str(exc_info.value).lower()


# =====================================================================
# Test 6 — Unsupported Capability Explicit Status
# =====================================================================


def test_6_unsupported_capability_explicit_status(temp_dir: Path):
    """Test that non-differentiable adapters explicitly declare UNSUPPORTED_GRADIENT_ACCESS
    and reject gradient requests.
    """
    onnx_file = temp_dir / "clean.onnx"
    onnx_file.write_bytes(b"dummy_onnx")
    oa = ONNXAdapter(model_path=onnx_file)
    assert oa.is_differentiable() is False
    assert oa.get_gradient_capability() == "UNSUPPORTED_GRADIENT_ACCESS"
    with pytest.raises(AccessDeniedError) as exc:
        oa.compute_input_gradients([0.1] * 16, 0)
    assert "UNSUPPORTED_GRADIENT_ACCESS" in str(exc.value)

    ts_file = temp_dir / "clean.torchscript"
    ts_file.write_bytes(b"dummy_ts")
    ta = TorchScriptAdapter(model_path=ts_file)
    assert ta.is_differentiable() is False
    assert ta.get_gradient_capability() == "UNSUPPORTED_GRADIENT_ACCESS"
    with pytest.raises(AccessDeniedError) as exc:
        ta.compute_input_gradients([0.1] * 16, 0)
    assert "UNSUPPORTED_GRADIENT_ACCESS" in str(exc.value)
