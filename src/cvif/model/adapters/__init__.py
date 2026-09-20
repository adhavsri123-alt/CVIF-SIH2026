"""Concrete model adapters for supported vision frameworks."""

from cvif.model.adapters.onnx_adapter import ONNXAdapter
from cvif.model.adapters.pytorch_adapter import PyTorchAdapter
from cvif.model.adapters.torchscript_adapter import TorchScriptAdapter

__all__ = [
    "ONNXAdapter",
    "PyTorchAdapter",
    "TorchScriptAdapter",
]
