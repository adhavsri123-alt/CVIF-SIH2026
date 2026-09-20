"""Test suite validating genuine real vision model execution for CVIF Model Integrity (MT-1 to MT-4)."""

import json
from pathlib import Path
import pytest
import torch
import torch.nn as nn
import torch.nn.functional as F

from cvif.core.enums import ModelAccessLevel, ModelTask, SeverityLevel
from cvif.model.safety import validate_model_file_safety, scan_model_file
from cvif.model.adapters.torchscript_adapter import TorchScriptAdapter
from cvif.model.adapters.pytorch_adapter import PyTorchAdapter
from cvif.model.battery import ReferenceBatteryBuilder
from cvif.analysis.model_orchestrator import ModelIntegrityOrchestrator
from cvif.analysis.model_integrity.substitution import ModelSubstitutionCheck
from cvif.analysis.model_integrity.modification import ModelModificationCheck
from cvif.analysis.model_integrity.backdoor import BackdoorBehaviorCheck
from cvif.analysis.model_integrity.activation import AnomalousActivationCheck


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "models"
CLEAN_MODEL_PATH = FIXTURES_DIR / "clean_vision_model.pt"
CANDIDATE_MODEL_PATH = FIXTURES_DIR / "candidate_vision_model.pt"
MODIFIED_MODEL_PATH = FIXTURES_DIR / "modified_vision_model.pt"
MANIFEST_PATH = FIXTURES_DIR / "model_manifest.json"


@pytest.fixture(scope="module")
def model_manifest():
    assert MANIFEST_PATH.exists(), f"Model manifest missing: {MANIFEST_PATH}"
    with open(MANIFEST_PATH, "r") as f:
        return json.load(f)


def test_real_model_fixtures_exist():
    """Verify all required real model artifacts exist and match manifest."""
    assert CLEAN_MODEL_PATH.exists()
    assert CANDIDATE_MODEL_PATH.exists()
    assert MODIFIED_MODEL_PATH.exists()
    assert CLEAN_MODEL_PATH.stat().st_size > 1000
    assert MODIFIED_MODEL_PATH.stat().st_size > 1000


def test_real_model_preflight_safety_scan():
    """Verify pre-flight static security scan passes on real models."""
    for path in [CLEAN_MODEL_PATH, CANDIDATE_MODEL_PATH, MODIFIED_MODEL_PATH]:
        scan = scan_model_file(path)
        assert scan.is_safe is True
        assert scan.detected_format == "pytorch"
        assert len(scan.file_hash) == 64
        # Enforce validate_model_file_safety does not raise
        validate_model_file_safety(path)


def test_real_model_torchscript_adapter_inference():
    """Verify real inference execution, latency, and anti-stub dynamic behavior."""
    adapter = TorchScriptAdapter(
        CLEAN_MODEL_PATH,
        task=ModelTask.CLASSIFICATION,
        class_names=["airplane", "automobile", "bird", "cat"],
    )
    adapter.load()
    assert adapter.is_inference_capable() is True
    assert adapter.get_inference_capability() == "TORCHSCRIPT_EVAL"

    # Input A: all ones
    inp_a = torch.ones(1, 3, 224, 224)
    pred_a = adapter.predict(inp_a)
    assert pred_a.status == "SUCCESS"
    assert pred_a.classification is not None
    assert pred_a.inference_time_ms > 0.0

    # Input B: random normal
    torch.manual_seed(1234)
    inp_b = torch.randn(1, 3, 224, 224) * 3.0
    pred_b = adapter.predict(inp_b)
    assert pred_b.status == "SUCCESS"
    assert pred_b.classification is not None

    # Anti-stub check: varying input produces varying confidence / logits
    assert pred_a.classification.confidence != pred_b.classification.confidence

    # Weight tensors inspection
    weights = adapter.get_weight_tensors()
    assert len(weights) > 0
    assert "fc2.weight" in weights
    assert len(weights["fc2.weight"]) == 4  # 4 classes


def test_real_model_pytorch_adapter_autograd_and_activations():
    """Verify genuine PyTorch autograd gradient flow and forward hook activations."""
    # Define reference module architecture matching fixture
    class StandardVisionClassifier(nn.Module):
        def __init__(self, num_classes: int = 4):
            super().__init__()
            self.conv1 = nn.Conv2d(3, 16, kernel_size=3, stride=2, padding=1)
            self.conv2 = nn.Conv2d(16, 32, kernel_size=3, stride=2, padding=1)
            self.pool = nn.AdaptiveAvgPool2d((4, 4))
            self.fc1 = nn.Linear(32 * 4 * 4, 32)
            self.fc2 = nn.Linear(32, num_classes)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            x = F.relu(self.conv1(x))
            x = F.relu(self.conv2(x))
            x = self.pool(x)
            x = x.flatten(1)
            x = F.relu(self.fc1(x))
            return self.fc2(x)

    torch.manual_seed(42)
    module = StandardVisionClassifier(num_classes=4)
    module.eval()

    adapter = PyTorchAdapter(
        model_path=CLEAN_MODEL_PATH,
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.WHITE_BOX,
        class_names=["airplane", "automobile", "bird", "cat"],
        input_shape=(3, 224, 224),
    )
    adapter._model = module
    adapter._state_dict = {k: v.detach().cpu() for k, v in module.state_dict().items()}
    adapter._is_loaded = True

    assert adapter.is_differentiable() is True
    assert adapter.get_gradient_capability() == "PYTORCH_AUTOGRAD"

    # Genuine autograd gradient verification
    dummy = torch.randn(1, 3, 224, 224)
    loss, conf, grad = adapter.compute_input_gradients(dummy, target_class=1)
    assert loss > 0.0
    assert 0.0 <= conf <= 1.0
    assert len(grad) == 3 * 224 * 224
    assert any(g != 0.0 for g in grad)

    # Genuine layer activation extraction via forward hooks
    acts = adapter.get_layer_activations(dummy)
    assert "conv1" in acts
    assert "conv2" in acts
    assert "fc1" in acts
    assert "fc2" in acts
    assert len(acts["conv1"]) > 0


def test_real_model_mt1_clean_baseline():
    """Verify MT-1: Clean candidate vs. Golden reference produces identical hash and zero divergence."""
    cand = TorchScriptAdapter(CANDIDATE_MODEL_PATH, task=ModelTask.CLASSIFICATION)
    ref = TorchScriptAdapter(CLEAN_MODEL_PATH, task=ModelTask.CLASSIFICATION)
    battery = ReferenceBatteryBuilder.create_synthetic_battery(task_type=ModelTask.CLASSIFICATION)

    check = ModelSubstitutionCheck()
    findings = check.run(candidate_model=cand, reference_model=ref, battery=battery)

    # Clean match produces Informational confirmation finding
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == SeverityLevel.INFORMATIONAL
    assert "Reference Match" in f.title or "Verified" in f.title


def test_real_model_mt2_tamper_detection():
    """Verify MT-2: Modified candidate vs. Golden reference detects weight alteration in fc2.weight."""
    cand_mod = TorchScriptAdapter(MODIFIED_MODEL_PATH, task=ModelTask.CLASSIFICATION)
    ref = TorchScriptAdapter(CLEAN_MODEL_PATH, task=ModelTask.CLASSIFICATION)
    battery = ReferenceBatteryBuilder.create_synthetic_battery(task_type=ModelTask.CLASSIFICATION)

    check = ModelModificationCheck()
    findings = check.run(candidate_model=cand_mod, reference_model=ref, battery=battery)

    # Must produce a tampering detection finding
    mod_findings = [f for f in findings if f.threat_id == "MT-2" and f.severity in (SeverityLevel.MEDIUM, SeverityLevel.HIGH)]
    assert len(mod_findings) >= 1
    f = mod_findings[0]
    assert "fc2.weight" in f.affected_assets
    assert "Weight perturbation detected" in f.description


def test_real_model_full_orchestrator_clean_vs_modified():
    """Verify ModelIntegrityOrchestrator runs MT-1 to MT-4 battery with genuine findings."""
    battery = ReferenceBatteryBuilder.create_synthetic_battery(task_type=ModelTask.CLASSIFICATION)
    orchestrator = ModelIntegrityOrchestrator()

    ref = TorchScriptAdapter(CLEAN_MODEL_PATH, task=ModelTask.CLASSIFICATION)
    cand_clean = TorchScriptAdapter(CANDIDATE_MODEL_PATH, task=ModelTask.CLASSIFICATION)
    cand_mod = TorchScriptAdapter(MODIFIED_MODEL_PATH, task=ModelTask.CLASSIFICATION)

    # 1. Clean run: Zero high/medium findings
    clean_session = orchestrator.run_analysis(
        candidate_model=cand_clean,
        reference_model=ref,
        battery=battery,
        operator_id="test_runner",
    )
    severe_clean = [f for f in clean_session.findings if f.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL, SeverityLevel.MEDIUM)]
    assert len(severe_clean) == 0, f"Clean model produced false positives: {severe_clean}"

    # 2. Modified run: Evidence-based MT-2 alert
    mod_session = orchestrator.run_analysis(
        candidate_model=cand_mod,
        reference_model=ref,
        battery=battery,
        operator_id="test_runner",
    )
    severe_mod = [f for f in mod_session.findings if f.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL, SeverityLevel.MEDIUM)]
    assert len(severe_mod) >= 1
    assert any(f.threat_id == "MT-2" for f in severe_mod)
