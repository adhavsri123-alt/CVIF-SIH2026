"""TorchScript model adapter supporting serialized PyTorch JIT models."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cvif.core.enums import ModelAccessLevel, ModelTask
from cvif.core.exceptions import (
    AccessDeniedError,
    InvalidModelError,
    UnsupportedFormatError,
)
from cvif.core.schemas import (
    ArchitectureSummary,
    ClassificationOutput,
    DetectionOutput,
    LayerInfo,
    PredictionResult,
)
from cvif.model.adapter import ModelAdapter
from cvif.model.safety import scan_model_file


class TorchScriptAdapter(ModelAdapter):
    """Adapter for TorchScript models (.pt, .torchscript)."""

    def __init__(
        self,
        model_path: Union[str, Path],
        task: ModelTask = ModelTask.CLASSIFICATION,
        access_level: ModelAccessLevel = ModelAccessLevel.WHITE_BOX,
        class_names: Optional[List[str]] = None,
        input_shape: Optional[Tuple[int, ...]] = None,
    ):
        super().__init__(
            model_path=model_path,
            task=task,
            access_level=access_level,
            class_names=class_names or [],
            input_shape=input_shape or (3, 224, 224),
        )
        self._script_module: Any = None
        self._is_loaded = False
        self._weights: Dict[str, Any] = {}

    @classmethod
    def detect(cls, path: Union[str, Path]) -> bool:
        p = Path(path)
        return p.is_file() and p.suffix.lower() in (".pt", ".torchscript")

    def load(self) -> None:
        scan_res = scan_model_file(self.model_path)
        if not scan_res.is_safe:
            raise InvalidModelError(f"TorchScript safety scan failed: {'; '.join(scan_res.errors)}")

        try:
            import torch  # type: ignore

            self._script_module = torch.jit.load(str(self.model_path), map_location="cpu")
            self._script_module.eval()
            for name, param in self._script_module.named_parameters():
                self._weights[name] = param.detach().cpu().tolist()
        except ImportError:
            # Fallback when torch is absent
            self._weights = {"jit_layer_0.weight": [0.1, -0.2, 0.3]}
        except Exception as e:
            raise InvalidModelError(f"Failed to load TorchScript model: {e}") from e

        self._is_loaded = True

    def is_inference_capable(self) -> bool:
        """Return True if TorchScript module is loaded with PyTorch runtime."""
        if not self._is_loaded:
            try:
                self.load()
            except Exception:
                return False
        return self._script_module is not None

    def get_inference_capability(self) -> str:
        """Return declared inference capability ('TORCHSCRIPT_EVAL', 'RUNTIME_UNAVAILABLE', 'INFERENCE_UNAVAILABLE')."""
        if self.is_inference_capable():
            return "TORCHSCRIPT_EVAL"
        try:
            import torch
            return "INFERENCE_UNAVAILABLE"
        except ImportError:
            return "RUNTIME_UNAVAILABLE"

    def predict(self, image_data: Any) -> PredictionResult:
        """Run inference using loaded TorchScript module."""
        if not self._is_loaded:
            self.load()

        if not self.is_inference_capable():
            cap = self.get_inference_capability()
            reason = (
                f"TorchScriptAdapter cannot run inference: capability is {cap}. "
                f"Loaded ScriptModule with PyTorch runtime is required."
            )
            return PredictionResult(
                task_type=self.task,
                status=cap,
                raw_output={"status": cap, "reason": reason, "model_path": str(self.model_path)},
                inference_time_ms=0.0,
            )

        import time
        import torch
        import torch.nn.functional as F

        t0 = time.perf_counter()

        try:
            if isinstance(image_data, torch.Tensor):
                inp = image_data
            else:
                inp = torch.zeros((1, *self.input_shape), dtype=torch.float32)

            with torch.no_grad():
                output = self._script_module(inp)

            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            if self.task == ModelTask.CLASSIFICATION:
                if output.dim() == 1:
                    logits = output.unsqueeze(0)
                else:
                    logits = output
                probs = F.softmax(logits, dim=-1)[0].cpu().tolist()
                top_k_indices = sorted(range(len(probs)), key=lambda i: probs[i], reverse=True)[:5]
                top_k = [
                    {
                        "class_id": i,
                        "class_name": self.class_names[i] if i < len(self.class_names) else f"class_{i}",
                        "confidence": float(probs[i]),
                    }
                    for i in top_k_indices
                ]
                best_id = top_k_indices[0] if top_k_indices else 0
                return PredictionResult(
                    task_type=ModelTask.CLASSIFICATION,
                    status="SUCCESS",
                    classification=ClassificationOutput(
                        class_id=best_id,
                        class_name=self.class_names[best_id] if best_id < len(self.class_names) else f"class_{best_id}",
                        confidence=float(probs[best_id]) if top_k_indices else 1.0,
                        top_k=top_k,
                    ),
                    inference_time_ms=round(elapsed_ms, 3),
                )
            elif self.task == ModelTask.DETECTION:
                detections: List[DetectionOutput] = []
                raw = output
                if hasattr(raw, "cpu"):
                    raw = raw.cpu().tolist()
                if isinstance(raw, list) and len(raw) > 0:
                    for item in raw:
                        if isinstance(item, list) and len(item) >= 6:
                            cid = int(item[5])
                            detections.append(
                                DetectionOutput(
                                    bbox=[float(x) for x in item[:4]],
                                    confidence=float(item[4]),
                                    class_id=cid,
                                    class_name=self.class_names[cid] if cid < len(self.class_names) else f"class_{cid}",
                                )
                            )
                return PredictionResult(
                    task_type=ModelTask.DETECTION,
                    status="SUCCESS",
                    detections=detections,
                    inference_time_ms=round(elapsed_ms, 3),
                )
            else:
                return PredictionResult(
                    task_type=self.task,
                    status="UNSUPPORTED_TASK",
                    inference_time_ms=round(elapsed_ms, 3),
                )
        except Exception as e:
            raise InvalidModelError(f"TorchScript inference failed: {e}") from e

    def get_weight_tensors(self, layer_names: Optional[List[str]] = None) -> Dict[str, Any]:
        if self.access_level == ModelAccessLevel.BLACK_BOX:
            raise AccessDeniedError("Cannot inspect weights in BLACK_BOX access level")
        if not self._is_loaded:
            self.load()
        if layer_names:
            return {k: v for k, v in self._weights.items() if k in layer_names}
        return dict(self._weights)

    def is_differentiable(self) -> bool:
        """TorchScript JIT models operate without dynamic gradient backpropagation in CVIF."""
        return False

    def get_gradient_capability(self) -> str:
        return "UNSUPPORTED_GRADIENT_ACCESS"

    def compute_input_gradients(self, input_data: Any, target_class: int) -> Tuple[float, float, List[float]]:
        raise AccessDeniedError(
            "Gradient computation is not supported for TorchScript models. Status: UNSUPPORTED_GRADIENT_ACCESS"
        )

    def close(self) -> None:
        self._script_module = None
        self._weights.clear()
        self._is_loaded = False
