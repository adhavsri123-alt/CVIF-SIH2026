"""Model adapter base abstractions and interface contracts."""

from abc import ABC, abstractmethod
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cvif.core.enums import ModelAccessLevel, ModelTask
from cvif.core.exceptions import AccessDeniedError, InvalidModelError
from cvif.core.schemas import (
    ArchitectureSummary,
    ClassificationOutput,
    DetectionOutput,
    LayerInfo,
    ParameterStats,
    PredictionResult,
    SegmentationOutput,
)


class ModelAdapter(ABC):
    """Abstract base class for all computer vision model adapters."""

    def __init__(
        self,
        model_path: Union[str, Path],
        task: ModelTask,
        access_level: ModelAccessLevel = ModelAccessLevel.BLACK_BOX,
        class_names: Optional[List[str]] = None,
        input_shape: Optional[Tuple[int, ...]] = None,
    ):
        self.model_path = Path(model_path)
        self.task = task
        self.access_level = access_level
        self.class_names = class_names or []
        self.input_shape = input_shape or (3, 224, 224)

    @classmethod
    def detect(cls, path: Union[str, Path]) -> bool:
        """Check if this adapter supports the given model file."""
        return False

    def load(self) -> None:
        """Load model assets into memory or runtime session."""
        pass

    def get_access_level(self) -> ModelAccessLevel:
        """Return the current model access level (WHITE_BOX, GREY_BOX, BLACK_BOX)."""
        return self.access_level

    def get_task_type(self) -> ModelTask:
        """Return declared or detected task type (CLASSIFICATION, DETECTION, etc.)."""
        return self.task

    @abstractmethod
    def predict(self, image_data: Any) -> PredictionResult:
        """Execute inference on input image data and return normalized PredictionResult."""
        raise NotImplementedError

    def predict_batch(self, inputs: List[Any]) -> List[PredictionResult]:
        """Execute inference on a batch of inputs."""
        return [self.predict(x) for x in inputs]

    def get_weight_digest(self) -> str:
        """Compute deterministic SHA-256 digest of internal parameter tensors."""
        if self.access_level == ModelAccessLevel.BLACK_BOX:
            raise AccessDeniedError(
                f"Cannot inspect model weights: access level is {self.access_level.value}, "
                f"WHITE_BOX or GREY_BOX access is required."
            )
        weights = self.get_weight_tensors()
        hasher = hashlib.sha256()
        for k in sorted(weights.keys()):
            hasher.update(k.encode("utf-8"))
            v = weights[k]
            if isinstance(v, bytes):
                hasher.update(v)
            elif isinstance(v, (list, tuple)):
                hasher.update(json.dumps(v, separators=(",", ":")).encode("utf-8"))
            else:
                hasher.update(str(v).encode("utf-8"))
        return hasher.hexdigest()

    def get_weights(self) -> Dict[str, Any]:
        """Legacy alias for get_weight_tensors."""
        return self.get_weight_tensors()

    def get_weight_tensors(self, layer_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """Access internal weight tensors. Permitted for WHITE_BOX and GREY_BOX."""
        if self.access_level == ModelAccessLevel.BLACK_BOX:
            raise AccessDeniedError(
                f"Cannot inspect model weights: access level is {self.access_level.value}, "
                f"WHITE_BOX or GREY_BOX access is required."
            )
        raise NotImplementedError("Concrete weight inspection must be implemented by subclass")

    def get_parameter_statistics(self) -> List[ParameterStats]:
        """Compute statistical properties of weights across accessible layers."""
        if self.access_level == ModelAccessLevel.BLACK_BOX:
            raise AccessDeniedError(
                f"Cannot compute parameter statistics: access level is {self.access_level.value}, "
                f"WHITE_BOX or GREY_BOX access is required."
            )
        weights = self.get_weight_tensors()
        stats: List[ParameterStats] = []
        for name, tensor in weights.items():
            flat = self._flatten_tensor(tensor)
            if not flat:
                continue
            n = len(flat)
            mean = sum(flat) / n
            var = sum((x - mean) ** 2 for x in flat) / n
            std = math.sqrt(var)
            l2_norm = math.sqrt(sum(x * x for x in flat))
            min_val = min(flat)
            max_val = max(flat)
            sparsity = sum(1 for x in flat if abs(x) < 1e-7) / n
            stats.append(
                ParameterStats(
                    layer_name=name,
                    shape=self._infer_shape(tensor),
                    total_elements=n,
                    mean=mean,
                    std=std,
                    l2_norm=l2_norm,
                    min_val=min_val,
                    max_val=max_val,
                    sparsity_ratio=sparsity,
                )
            )
        return stats

    def get_architecture_summary(self) -> ArchitectureSummary:
        """Produce structured overview of layers, parameters, and framework details."""
        if self.access_level == ModelAccessLevel.BLACK_BOX:
            raise AccessDeniedError(
                f"Cannot access architecture summary: access level is {self.access_level.value}, "
                f"WHITE_BOX or GREY_BOX access is required."
            )
        layers = self.enumerate_layers()
        total_p = sum(l.parameters_count for l in layers)
        trainable_p = sum(l.parameters_count for l in layers if l.trainable)
        return ArchitectureSummary(
            total_parameters=total_p,
            trainable_parameters=trainable_p,
            non_trainable_parameters=total_p - trainable_p,
            layers=layers,
            framework="generic",
            model_family="custom",
        )

    def enumerate_layers(self) -> List[LayerInfo]:
        """Enumerate structural layers in the network graph."""
        if self.access_level == ModelAccessLevel.BLACK_BOX:
            raise AccessDeniedError(
                f"Cannot enumerate layers: access level is {self.access_level.value}, "
                f"WHITE_BOX or GREY_BOX access is required."
            )
        weights = self.get_weight_tensors()
        layers: List[LayerInfo] = []
        for name, tensor in weights.items():
            shape = self._infer_shape(tensor)
            count = 1
            for d in shape:
                count *= d
            layers.append(
                LayerInfo(
                    name=name,
                    layer_type="dense_or_conv",
                    shape=shape,
                    trainable=True,
                    parameters_count=count,
                )
            )
        return layers

    def get_layer_activations(self, image_data: Any, layer_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """Inspect internal layer activations. Only permitted for WHITE_BOX models."""
        if self.access_level != ModelAccessLevel.WHITE_BOX:
            raise AccessDeniedError(
                f"Cannot inspect activations: access level is {self.access_level.value}, "
                f"WHITE_BOX access is required."
            )
        raise NotImplementedError("Concrete activation extraction must be implemented by subclass")

    def get_intermediate_outputs(self, image_data: Any, node_names: List[str]) -> Dict[str, Any]:
        """Inspect intermediate node outputs. Permitted for WHITE_BOX and GREY_BOX."""
        if self.access_level == ModelAccessLevel.BLACK_BOX:
            raise AccessDeniedError(
                f"Cannot inspect intermediate outputs: access level is {self.access_level.value}, "
                f"WHITE_BOX or GREY_BOX access is required."
            )
        raise NotImplementedError("Concrete intermediate extraction must be implemented by subclass")

    def is_inference_capable(self) -> bool:
        """Return True if this model adapter has an active runtime and executable graph for inference."""
        return False

    def get_inference_capability(self) -> str:
        """Return declared inference capability ('PYTORCH_EVAL', 'ONNX_RUNTIME', 'TORCHSCRIPT_EVAL', 'MOCK_INFERENCE', 'RUNTIME_UNAVAILABLE', 'INFERENCE_UNAVAILABLE')."""
        return "INFERENCE_UNAVAILABLE"

    def is_differentiable(self) -> bool:
        """Return True if this model adapter supports gradient computation and input optimization."""
        return False

    def get_gradient_capability(self) -> str:
        """Return declared gradient computation capability ('PYTORCH_AUTOGRAD', 'ANALYTICAL_GRADIENT', 'UNSUPPORTED_GRADIENT_ACCESS')."""
        return "UNSUPPORTED_GRADIENT_ACCESS"

    def compute_input_gradients(self, input_data: Any, target_class: int) -> Tuple[float, float, List[float]]:
        """Compute cross-entropy loss, target class confidence, and gradient w.r.t input_data.

        Args:
            input_data: Input image tensor, feature vector, or raw image data.
            target_class: Target class index to evaluate loss and gradient against.

        Returns:
            Tuple[float, float, List[float]]: (loss, target_confidence, grad_wrt_input)
        """
        if self.access_level != ModelAccessLevel.WHITE_BOX:
            raise AccessDeniedError(
                f"Cannot compute input gradients: access level is {self.access_level.value}, "
                f"WHITE_BOX access is required."
            )
        raise NotImplementedError("Concrete input gradient computation must be implemented by subclass")

    def get_gradients(self, image_data: Any, target_class: int) -> Any:
        """Compute loss gradients w.r.t input. Only permitted for WHITE_BOX models."""
        if self.access_level != ModelAccessLevel.WHITE_BOX:
            raise AccessDeniedError(
                f"Cannot compute gradients: access level is {self.access_level.value}, "
                f"WHITE_BOX access is required."
            )
        raise NotImplementedError("Concrete gradient computation must be implemented by subclass")

    def close(self) -> None:
        """Release any held hardware/GPU resources."""
        pass

    def unload(self) -> None:
        """Alias for close()."""
        self.close()

    def _flatten_tensor(self, tensor: Any) -> List[float]:
        """Helper to recursively flatten nested lists or arrays into float list."""
        if isinstance(tensor, (int, float)):
            return [float(tensor)]
        if hasattr(tensor, "flatten") and hasattr(tensor, "tolist"):
            return [float(x) for x in tensor.flatten().tolist()]
        if isinstance(tensor, (list, tuple)):
            res: List[float] = []
            for item in tensor:
                res.extend(self._flatten_tensor(item))
            return res
        return []

    def _infer_shape(self, tensor: Any) -> List[int]:
        """Helper to infer shape of nested list or array."""
        if hasattr(tensor, "shape"):
            return list(tensor.shape)
        if isinstance(tensor, (list, tuple)):
            if not tensor:
                return [0]
            sub = self._infer_shape(tensor[0])
            return [len(tensor)] + sub
        return []


class MockModelAdapter(ModelAdapter):
    """Configurable mock adapter for deterministic testing of all assurance algorithms."""

    def __init__(
        self,
        task: ModelTask = ModelTask.CLASSIFICATION,
        access_level: ModelAccessLevel = ModelAccessLevel.BLACK_BOX,
        mock_output: Optional[PredictionResult] = None,
        mock_weights: Optional[Dict[str, Any]] = None,
        mock_activations: Optional[Dict[str, Any]] = None,
        mock_gradients: Optional[Dict[str, Any]] = None,
        backdoor_target_class: Optional[int] = None,
        class_names: Optional[List[str]] = None,
    ):
        super().__init__(
            model_path="mock://model.bin",
            task=task,
            access_level=access_level,
            class_names=class_names or ["military_vehicle", "civilian_car", "aerial_drone", "radar_station"],
        )
        self._mock_output = mock_output
        self._mock_weights = mock_weights or {
            "conv1.weight": [[0.1, -0.2], [0.3, 0.4]],
            "conv2.weight": [[-0.05, 0.15], [0.25, -0.35]],
            "fc.weight": [[0.5, -0.5], [0.2, -0.1]],
        }
        self._mock_activations = mock_activations or {
            "conv1": [0.8, 0.5, 0.0, 0.0],
            "conv2": [0.3, 0.9, 0.0, 0.1],
            "fc": [0.95, 0.02, 0.01, 0.02],
        }
        self._mock_gradients = mock_gradients or {
            "input_grad": [0.01, -0.02, 0.03, -0.01],
        }
        self.backdoor_target_class = backdoor_target_class
        self._predict_call_count = 0

        # Differentiable linear/MLP classifier parameters for white-box classification
        self._diff_dim = 16
        num_classes = len(self.class_names)
        import random
        rng = random.Random(42)
        self._diff_W = [
            [round(rng.gauss(0.0, 0.2), 4) for _ in range(self._diff_dim)]
            for _ in range(num_classes)
        ]
        self._diff_b = [0.0] * num_classes

        # If a backdoor target class is provided at initialization on a white-box model,
        # inject the trojan directly into the model's actual weight matrix W:
        if backdoor_target_class is not None and 0 <= backdoor_target_class < num_classes:
            self.inject_backdoor_trojan(backdoor_target_class, feature_indices=[0, 1], weight=8.0)

    def predict(self, image_data: Any) -> PredictionResult:
        self._predict_call_count += 1
        if self._mock_output is not None:
            return self._mock_output

        # Check for simulated backdoor activation on perturbed inputs
        is_triggered = False
        if hasattr(image_data, "perturbation_type") and image_data.perturbation_type:
            is_triggered = True
        elif isinstance(image_data, dict) and image_data.get("perturbation_type"):
            is_triggered = True

        if self.task == ModelTask.CLASSIFICATION:
            target_cls = 0
            conf = 0.95
            if is_triggered and self.backdoor_target_class is not None:
                target_cls = self.backdoor_target_class
                conf = 0.99

            num_classes = len(self.class_names)
            top_k = []
            for i in range(min(5, num_classes)):
                c_conf = conf if i == target_cls else round((1.0 - conf) / (num_classes - 1), 4)
                top_k.append({
                    "class_id": i,
                    "class_name": self.class_names[i],
                    "confidence": c_conf,
                })
            top_k.sort(key=lambda x: x["confidence"], reverse=True)

            return PredictionResult(
                task_type=ModelTask.CLASSIFICATION,
                classification=ClassificationOutput(
                    class_id=target_cls,
                    class_name=self.class_names[target_cls],
                    confidence=conf,
                    top_k=top_k,
                ),
            )

        elif self.task == ModelTask.DETECTION:
            if is_triggered and self.backdoor_target_class is not None:
                # Simulated evasion backdoor: target class detections completely vanish!
                return PredictionResult(
                    task_type=ModelTask.DETECTION,
                    detections=[],
                )
            return PredictionResult(
                task_type=ModelTask.DETECTION,
                detections=[
                    DetectionOutput(
                        bbox=[0.1, 0.1, 0.5, 0.5],
                        class_id=0,
                        class_name=self.class_names[0] if self.class_names else "target",
                        confidence=0.88,
                    )
                ],
            )
        else:
            return PredictionResult(task_type=self.task)

    def get_weight_tensors(self, layer_names: Optional[List[str]] = None) -> Dict[str, Any]:
        if self.access_level == ModelAccessLevel.BLACK_BOX:
            raise AccessDeniedError(
                f"Cannot inspect model weights: access level is {self.access_level.value}, "
                f"WHITE_BOX or GREY_BOX access is required."
            )
        if layer_names:
            return {k: v for k, v in self._mock_weights.items() if k in layer_names}
        return dict(self._mock_weights)

    def get_layer_activations(self, image_data: Any, layer_names: Optional[List[str]] = None) -> Dict[str, Any]:
        if self.access_level != ModelAccessLevel.WHITE_BOX:
            raise AccessDeniedError(
                f"Cannot inspect activations: access level is {self.access_level.value}, "
                f"WHITE_BOX access is required."
            )
        if layer_names:
            return {k: v for k, v in self._mock_activations.items() if k in layer_names}
        return dict(self._mock_activations)

    def get_intermediate_outputs(self, image_data: Any, node_names: List[str]) -> Dict[str, Any]:
        if self.access_level == ModelAccessLevel.BLACK_BOX:
            raise AccessDeniedError(
                f"Cannot inspect intermediate outputs: access level is {self.access_level.value}, "
                f"WHITE_BOX or GREY_BOX access is required."
            )
        return {k: v for k, v in self._mock_activations.items() if k in node_names}

    def get_gradients(self, image_data: Any, target_class: int) -> Dict[str, Any]:
        if self.access_level != ModelAccessLevel.WHITE_BOX:
            raise AccessDeniedError(
                f"Cannot compute gradients: access level is {self.access_level.value}, "
                f"WHITE_BOX access is required."
            )
        return dict(self._mock_gradients)

    def inject_backdoor_trojan(
        self,
        target_class: int,
        feature_indices: Optional[List[int]] = None,
        weight: float = 8.0,
    ) -> None:
        """Inject a physical backdoor trojan into the differentiable weight matrix."""
        if not hasattr(self, "_diff_W"):
            return
        indices = feature_indices or [0, 1]
        num_classes = len(self.class_names)
        if 0 <= target_class < num_classes:
            for idx in indices:
                if idx < self._diff_dim:
                    self._diff_W[target_class][idx] = weight
                    for c in range(num_classes):
                        if c != target_class:
                            self._diff_W[c][idx] = -weight / 4.0

    def is_inference_capable(self) -> bool:
        return True

    def get_inference_capability(self) -> str:
        return "MOCK_INFERENCE"

    def is_differentiable(self) -> bool:
        """Return True if white-box access is granted and differentiable classifier is present."""
        return self.access_level == ModelAccessLevel.WHITE_BOX and hasattr(self, "_diff_W")

    def get_gradient_capability(self) -> str:
        if self.is_differentiable():
            return "ANALYTICAL_GRADIENT"
        return "UNSUPPORTED_GRADIENT_ACCESS"

    def _to_input_vector(self, input_data: Any, dim: int = 16) -> List[float]:
        """Convert arbitrary image input, bytes, or array into normalized float vector."""
        if isinstance(input_data, (list, tuple)):
            flat = self._flatten_tensor(input_data)
            if len(flat) >= dim:
                return flat[:dim]
            return flat + [0.1] * (dim - len(flat))
        if hasattr(input_data, "image_bytes") and input_data.image_bytes:
            raw = input_data.image_bytes
        elif isinstance(input_data, (bytes, bytearray)):
            raw = bytes(input_data)
        else:
            raw = str(input_data).encode("utf-8")
        if not raw:
            return [0.1] * dim
        res = []
        for i in range(dim):
            idx = (i * 7 + 13) % len(raw)
            res.append(round(raw[idx] / 255.0, 4))
        return res

    def compute_input_gradients(self, input_data: Any, target_class: int) -> Tuple[float, float, List[float]]:
        """Compute cross-entropy loss, target class confidence, and gradient w.r.t input_data."""
        if self.access_level != ModelAccessLevel.WHITE_BOX:
            raise AccessDeniedError(
                f"Cannot compute input gradients: access level is {self.access_level.value}, "
                f"WHITE_BOX access is required."
            )
        if not hasattr(self, "_diff_W"):
            raise NotImplementedError("Differentiable weights not initialized on this mock")

        x = self._to_input_vector(input_data, self._diff_dim)
        num_classes = len(self.class_names)
        if not (0 <= target_class < num_classes):
            raise ValueError(f"Invalid target class index {target_class}; model has {num_classes} classes")

        logits = [
            sum(self._diff_W[c][j] * x[j] for j in range(self._diff_dim)) + self._diff_b[c]
            for c in range(num_classes)
        ]
        max_z = max(logits)
        exp_z = [math.exp(z - max_z) for z in logits]
        sum_exp = sum(exp_z)
        probs = [e / sum_exp for e in exp_z]

        target_prob = probs[target_class]
        loss_ce = -math.log(max(target_prob, 1e-12))

        g_z = [probs[c] - (1.0 if c == target_class else 0.0) for c in range(num_classes)]
        g_x = [
            sum(g_z[c] * self._diff_W[c][j] for c in range(num_classes))
            for j in range(self._diff_dim)
        ]
        return loss_ce, target_prob, g_x
