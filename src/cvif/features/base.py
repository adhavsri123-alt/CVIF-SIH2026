"""Base interface and contracts for computer vision feature extractors."""

from abc import ABC, abstractmethod
from typing import Any, List


class FeatureExtractor(ABC):
    """Abstract interface for extracting dense semantic or statistical feature embeddings."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name or architecture of the feature extractor."""
        raise NotImplementedError

    @property
    @abstractmethod
    def embedding_dim(self) -> int:
        """Fixed dimensionality of the output embedding vector."""
        raise NotImplementedError

    @property
    def device(self) -> str:
        """Execution device ('cpu', 'cuda', etc.)."""
        return "cpu"

    @abstractmethod
    def extract(self, image_input: Any) -> List[float]:
        """Extract a 1D feature vector normalized to unit length."""
        raise NotImplementedError

    def extract_batch(self, image_inputs: List[Any]) -> List[List[float]]:
        """Extract feature vectors for a batch of images."""
        return [self.extract(img) for img in image_inputs]


class MockFeatureExtractor(FeatureExtractor):
    """Safe mock feature extractor for testing interface contracts."""

    def __init__(self, dim: int = 128, name: str = "mock_extractor"):
        self._dim = dim
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def embedding_dim(self) -> int:
        return self._dim

    def extract(self, image_input: Any) -> List[float]:
        # Return deterministic vector based on input hash or fixed dummy vector
        import hashlib
        import struct

        if isinstance(image_input, (bytes, bytearray)):
            h = hashlib.sha256(image_input).digest()
        else:
            h = hashlib.sha256(str(image_input).encode("utf-8")).digest()

        # Seed pseudo-random reproducible vector
        vec: List[float] = []
        for i in range(self._dim):
            byte_val = h[i % len(h)]
            vec.append((byte_val / 255.0) - 0.5)

        # Normalize to unit length
        norm = sum(x * x for x in vec) ** 0.5 or 1.0
        return [x / norm for x in vec]
