"""Pure-Python fallback statistical feature extractor for air-gapped environments."""

import math
from pathlib import Path
from typing import Any, List, Union

from cvif.core.exceptions import CVIFStorageError
from cvif.features.base import FeatureExtractor


class StatisticalFeatureExtractor(FeatureExtractor):
    """Air-gapped fallback feature extractor using deterministic multi-scale statistics.
    
    Operates without external pre-trained neural weights, ensuring functionality in fully isolated
    environments when deep backbones are unavailable or unverified.
    """

    def __init__(self, dim: int = 128):
        self._dim = dim

    @property
    def name(self) -> str:
        return "statistical_fallback_v1"

    @property
    def embedding_dim(self) -> int:
        return self._dim

    def extract(self, image_input: Any) -> List[float]:
        """Extract multi-scale statistical features from raw image bytes or path."""
        data: bytes
        if isinstance(image_input, (bytes, bytearray)):
            data = bytes(image_input)
        elif isinstance(image_input, (str, Path)):
            p = Path(image_input)
            if not p.is_file():
                raise CVIFStorageError(f"Image file not found: {p}")
            data = p.read_bytes()
        else:
            data = str(image_input).encode("utf-8")

        if not data:
            return [0.0] * self._dim

        # Compute multi-channel distribution statistics across the byte stream
        # 1. Byte histogram downsampled to 64 bins
        hist = [0] * 64
        for b in data:
            hist[b // 4] += 1
        total = len(data)
        norm_hist = [count / total for count in hist]

        # 2. Statistical moments (mean, variance, skewness, kurtosis)
        mean_val = sum(b for b in data) / total
        variance = sum((b - mean_val) ** 2 for b in data) / total
        std_dev = math.sqrt(variance) if variance > 0 else 1e-6
        skewness = (sum((b - mean_val) ** 3 for b in data) / total) / (std_dev**3)
        kurtosis = (sum((b - mean_val) ** 4 for b in data) / total) / (std_dev**4)

        moments = [mean_val / 255.0, std_dev / 255.0, skewness / 10.0, kurtosis / 50.0]

        # 3. Spatial delta / gradient approximations (differences between consecutive bytes)
        deltas = [abs(data[i] - data[i - 1]) for i in range(1, min(len(data), 1000))]
        delta_mean = (sum(deltas) / len(deltas) / 255.0) if deltas else 0.0
        delta_max = (max(deltas) / 255.0) if deltas else 0.0

        grad_stats = [delta_mean, delta_max]

        # Combine into target dimension
        combined = norm_hist + moments + grad_stats
        # Pad or slice to exact self._dim
        if len(combined) < self._dim:
            # Repeat or pad
            padding = [0.0] * (self._dim - len(combined))
            combined.extend(padding)
        else:
            combined = combined[: self._dim]

        # Unit length normalization
        norm = math.sqrt(sum(x * x for x in combined))
        if norm > 0:
            return [x / norm for x in combined]
        return combined
