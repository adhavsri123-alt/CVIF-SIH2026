"""Unit tests for ModelAdapter, DatasetAdapter, FeatureExtractor, and model safety."""

from pathlib import Path
import pytest

from cvif.core.enums import ModelAccessLevel, ModelTask
from cvif.core.exceptions import AccessDeniedError, InvalidModelError, UnsupportedFormatError
from cvif.core.schemas import PredictionResult, DetectionOutput
from cvif.model.adapter import MockModelAdapter
from cvif.model.safety import validate_model_file_safety
from cvif.ingestion.adapters.base import MockDatasetAdapter
from cvif.features.base import MockFeatureExtractor
from cvif.features.statistical import StatisticalFeatureExtractor


def test_model_adapter_black_box_restrictions():
    adapter = MockModelAdapter(
        task=ModelTask.CLASSIFICATION,
        access_level=ModelAccessLevel.BLACK_BOX,
    )

    # Black-box prediction works
    res = adapter.predict(b"raw_image_data")
    assert isinstance(res, PredictionResult)
    assert res.task_type == ModelTask.CLASSIFICATION
    assert res.classification.confidence == 0.95

    # White-box inspection methods must be denied
    with pytest.raises(AccessDeniedError):
        adapter.get_weights()

    with pytest.raises(AccessDeniedError):
        adapter.get_layer_activations(b"image", ["conv1"])

    with pytest.raises(AccessDeniedError):
        adapter.get_gradients(b"image", target_class=0)


def test_model_adapter_detection_output():
    adapter = MockModelAdapter(
        task=ModelTask.DETECTION,
        access_level=ModelAccessLevel.BLACK_BOX,
    )
    res = adapter.predict(b"image_data")
    assert res.task_type == ModelTask.DETECTION
    assert len(res.detections) == 1
    det = res.detections[0]
    assert isinstance(det, DetectionOutput)
    assert det.bbox == [0.1, 0.1, 0.5, 0.5]


def test_dataset_adapter_contracts():
    adapter = MockDatasetAdapter()
    assert adapter.sample_count == 5
    assert adapter.format_name == "mock"
    assert len(adapter.class_names) == 2

    val_res = adapter.validate()
    assert val_res.is_valid is True
    assert val_res.total_samples == 5

    samples = list(adapter.iter_samples())
    assert len(samples) == 5
    assert samples[0]["sample_id"] == "sample_0"

    with pytest.raises(IndexError):
        adapter.get_sample(99)


def test_feature_extractor_contracts():
    extractor = MockFeatureExtractor(dim=64)
    assert extractor.embedding_dim == 64
    assert extractor.name == "mock_extractor"

    emb = extractor.extract(b"image_sample_1")
    assert len(emb) == 64
    # Unit normalized
    norm = sum(x * x for x in emb) ** 0.5
    assert abs(norm - 1.0) < 1e-4

    batch = extractor.extract_batch([b"img1", b"img2"])
    assert len(batch) == 2
    assert len(batch[0]) == 64


def test_statistical_feature_extractor_offline():
    extractor = StatisticalFeatureExtractor(dim=128)
    assert extractor.embedding_dim == 128
    assert extractor.name == "statistical_fallback_v1"

    raw_bytes = bytes([i % 256 for i in range(5000)])
    emb = extractor.extract(raw_bytes)
    assert len(emb) == 128
    # Unit normalized
    norm = sum(x * x for x in emb) ** 0.5
    assert abs(norm - 1.0) < 1e-4

    # Determinism: same input produces identical embedding
    emb2 = extractor.extract(raw_bytes)
    assert emb == emb2


def test_model_file_safety(temp_dir: Path):
    # Valid ONNX
    onnx_file = temp_dir / "valid_model.onnx"
    onnx_file.write_bytes(b"dummy_onnx_header_content_12345")
    assert validate_model_file_safety(onnx_file) == "onnx"

    # Unsupported format
    sh_file = temp_dir / "script.sh"
    sh_file.write_bytes(b"#!/bin/bash\necho hello")
    with pytest.raises(UnsupportedFormatError):
        validate_model_file_safety(sh_file)

    # Empty file
    empty_file = temp_dir / "empty.pt"
    empty_file.write_bytes(b"")
    with pytest.raises(InvalidModelError):
        validate_model_file_safety(empty_file)

    # Malicious pickle payload
    evil_file = temp_dir / "evil.pt"
    evil_file.write_bytes(b"cos\nsystem\n(S'calc.exe'tRp1.")
    with pytest.raises(InvalidModelError) as exc_info:
        validate_model_file_safety(evil_file)
    assert "dangerous opcode" in str(exc_info.value)
