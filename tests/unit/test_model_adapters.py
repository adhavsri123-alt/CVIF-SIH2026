"""Unit tests for ModelAdapter hierarchy, concrete adapters, and access level boundaries."""

from pathlib import Path
import pytest

from cvif.core.enums import ModelAccessLevel, ModelTask
from cvif.core.exceptions import AccessDeniedError, InvalidModelError
from cvif.core.schemas import (
    ArchitectureSummary,
    ClassificationOutput,
    DetectionOutput,
    ParameterStats,
    PredictionResult,
)
from cvif.model.adapter import MockModelAdapter, ModelAdapter
from cvif.model.adapters.onnx_adapter import ONNXAdapter
from cvif.model.adapters.pytorch_adapter import PyTorchAdapter
from cvif.model.adapters.torchscript_adapter import TorchScriptAdapter


def test_mock_adapter_access_level_boundaries():
    """Verify access level matrix for BLACK_BOX, GREY_BOX, and WHITE_BOX."""
    # 1. BLACK_BOX: Only inference permitted
    bb = MockModelAdapter(access_level=ModelAccessLevel.BLACK_BOX)
    assert bb.get_access_level() == ModelAccessLevel.BLACK_BOX
    assert isinstance(bb.predict(b"img"), PredictionResult)

    with pytest.raises(AccessDeniedError):
        bb.get_weight_tensors()
    with pytest.raises(AccessDeniedError):
        bb.get_parameter_statistics()
    with pytest.raises(AccessDeniedError):
        bb.get_layer_activations(b"img")
    with pytest.raises(AccessDeniedError):
        bb.get_gradients(b"img", 0)
    with pytest.raises(AccessDeniedError):
        bb.enumerate_layers()
    with pytest.raises(AccessDeniedError):
        bb.get_architecture_summary()
    with pytest.raises(AccessDeniedError):
        bb.get_intermediate_outputs(b"img", ["node"])

    # 2. GREY_BOX: Weights, parameter stats, intermediate outputs permitted; hooks & gradients denied
    gb = MockModelAdapter(access_level=ModelAccessLevel.GREY_BOX)
    assert gb.get_access_level() == ModelAccessLevel.GREY_BOX
    assert isinstance(gb.get_weight_tensors(), dict)
    assert len(gb.get_parameter_statistics()) > 0
    assert isinstance(gb.get_intermediate_outputs(b"img", ["conv1"]), dict)
    assert len(gb.get_weight_digest()) == 64

    with pytest.raises(AccessDeniedError):
        gb.get_layer_activations(b"img")
    with pytest.raises(AccessDeniedError):
        gb.get_gradients(b"img", 0)

    # 3. WHITE_BOX: All capabilities permitted
    wb = MockModelAdapter(access_level=ModelAccessLevel.WHITE_BOX)
    assert wb.get_access_level() == ModelAccessLevel.WHITE_BOX
    assert isinstance(wb.get_weight_tensors(), dict)
    assert len(wb.get_parameter_statistics()) > 0
    assert isinstance(wb.get_layer_activations(b"img"), dict)
    assert isinstance(wb.get_gradients(b"img", 0), dict)
    assert isinstance(wb.get_architecture_summary(), ArchitectureSummary)
    assert len(wb.enumerate_layers()) > 0


def test_parameter_statistics_calculation():
    """Verify statistical computation (mean, std, l2_norm, sparsity) on weight tensors."""
    custom_weights = {
        "layer_zeros": [0.0, 0.0, 0.0, 0.0],
        "layer_ones": [1.0, 1.0, 1.0, 1.0],
        "layer_mixed": [2.0, -2.0, 0.0, 0.0],
    }
    model = MockModelAdapter(
        access_level=ModelAccessLevel.WHITE_BOX,
        mock_weights=custom_weights,
    )
    stats = model.get_parameter_statistics()
    stats_dict = {s.layer_name: s for s in stats}

    # Zeros layer
    s_zeros = stats_dict["layer_zeros"]
    assert s_zeros.mean == 0.0
    assert s_zeros.std == 0.0
    assert s_zeros.l2_norm == 0.0
    assert s_zeros.sparsity_ratio == 1.0

    # Ones layer
    s_ones = stats_dict["layer_ones"]
    assert s_ones.mean == 1.0
    assert s_ones.std == 0.0
    assert s_ones.l2_norm == 2.0
    assert s_ones.sparsity_ratio == 0.0

    # Mixed layer
    s_mixed = stats_dict["layer_mixed"]
    assert s_mixed.mean == 0.0
    assert abs(s_mixed.l2_norm - (8.0 ** 0.5)) < 1e-4
    assert s_mixed.sparsity_ratio == 0.5


def test_pytorch_adapter_contracts(temp_dir: Path):
    """Verify PyTorchAdapter safe loading and white-box contracts."""
    pt_file = temp_dir / "model.pt"
    try:
        import torch
        torch.save({"layer1.weight": torch.tensor([0.1, 0.2, 0.3])}, pt_file)
    except ImportError:
        pt_file.write_bytes(b"dummy_pytorch_model_payload_12345")

    adapter = PyTorchAdapter(
        model_path=pt_file,
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
        class_names=["tank", "truck", "drone"],
    )
    assert PyTorchAdapter.detect(pt_file) is True
    assert PyTorchAdapter.detect(temp_dir / "other.bin") is False

    adapter.load()
    assert adapter._is_loaded is True

    # Prediction
    pred = adapter.predict(b"test_image")
    assert isinstance(pred, PredictionResult)
    assert pred.task_type == ModelTask.CLASSIFICATION
    if adapter.is_inference_capable():
        assert pred.status == "SUCCESS"
        assert pred.classification is not None
    else:
        assert pred.status in ("RUNTIME_UNAVAILABLE", "STATE_DICT_ONLY", "INFERENCE_UNAVAILABLE")
        assert pred.classification is None

    # Weights and statistics
    weights = adapter.get_weight_tensors()
    assert isinstance(weights, dict)
    stats = adapter.get_parameter_statistics()
    assert isinstance(stats, list)

    # Activations
    acts = adapter.get_layer_activations(b"test_image")
    assert isinstance(acts, dict)

    adapter.close()
    assert adapter._is_loaded is False


def test_onnx_adapter_contracts(temp_dir: Path):
    """Verify ONNXAdapter defaults to GREY_BOX and enforces capability limitations."""
    onnx_file = temp_dir / "model.onnx"
    onnx_file.write_bytes(b"dummy_onnx_model_payload_12345")

    adapter = ONNXAdapter(
        model_path=onnx_file,
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.GREY_BOX,
    )
    assert ONNXAdapter.detect(onnx_file) is True
    assert adapter.get_access_level() == ModelAccessLevel.GREY_BOX

    adapter.load()

    # Inference capability check
    pred = adapter.predict(b"image")
    assert isinstance(pred, PredictionResult)
    if adapter.is_inference_capable():
        assert pred.status == "SUCCESS"
    else:
        assert pred.status in ("RUNTIME_UNAVAILABLE", "INFERENCE_UNAVAILABLE")
        assert pred.classification is None

    # Grey-box weight inspection works
    weights = adapter.get_weight_tensors()
    assert isinstance(weights, dict)
    assert len(adapter.get_weight_digest()) == 64

    # Activations and gradients are denied in GREY_BOX
    with pytest.raises(AccessDeniedError):
        adapter.get_layer_activations(b"image")

    with pytest.raises(AccessDeniedError):
        adapter.get_gradients(b"image", 0)

    adapter.close()


def test_torchscript_adapter_contracts(temp_dir: Path):
    """Verify TorchScriptAdapter loading and inference."""
    ts_file = temp_dir / "model.torchscript"
    try:
        import torch
        class DummyModule(torch.nn.Module):
            def forward(self, x: torch.Tensor) -> torch.Tensor:
                return torch.tensor([[0.1, 0.1, 0.5, 0.5, 0.95, 0.0]])
        torch.jit.script(DummyModule()).save(str(ts_file))
    except Exception:
        ts_file.write_bytes(b"dummy_torchscript_payload_12345")

    adapter = TorchScriptAdapter(
        model_path=ts_file,
        task=ModelTask.DETECTION,
    )
    assert TorchScriptAdapter.detect(ts_file) is True
    adapter.load()

    pred = adapter.predict(b"image")
    assert isinstance(pred, PredictionResult)
    if adapter.is_inference_capable():
        assert pred.task_type == ModelTask.DETECTION
        assert len(pred.detections) > 0
    else:
        assert pred.status in ("RUNTIME_UNAVAILABLE", "INFERENCE_UNAVAILABLE")
        assert pred.detections is None

    weights = adapter.get_weight_tensors()
    assert isinstance(weights, dict)
    adapter.close()
