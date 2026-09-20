"""Base abstractions for dataset adapters (COCO, YOLO, custom)."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Union

from cvif.core.schemas import ValidationResult


class DatasetAdapter(ABC):
    """Abstract interface for ingesting and validating computer vision training/eval datasets."""

    def __init__(self, dataset_path: Union[str, Path]):
        self.dataset_path = Path(dataset_path)

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Name of the dataset format (e.g., 'coco', 'yolo')."""
        raise NotImplementedError

    @property
    @abstractmethod
    def sample_count(self) -> int:
        """Total number of accessible samples."""
        raise NotImplementedError

    @property
    @abstractmethod
    def class_names(self) -> List[str]:
        """List of target class names declared in dataset."""
        raise NotImplementedError

    @abstractmethod
    def validate(self) -> ValidationResult:
        """Validate structure, manifest consistency, and image existence."""
        raise NotImplementedError

    @abstractmethod
    def get_sample(self, index: int) -> Dict[str, Any]:
        """Fetch sample metadata and file references by 0-based index."""
        raise NotImplementedError

    def iter_samples(self) -> Generator[Dict[str, Any], None, None]:
        """Iterate over all samples in dataset sequence."""
        for i in range(self.sample_count):
            yield self.get_sample(i)

    def close(self) -> None:
        """Release any file descriptors or locks."""
        pass


class MockDatasetAdapter(DatasetAdapter):
    """Safe mock dataset adapter used strictly for testing foundation contracts."""

    def __init__(
        self,
        samples: Optional[List[Dict[str, Any]]] = None,
        format_name: str = "mock",
        class_names: Optional[List[str]] = None,
    ):
        super().__init__(dataset_path="mock://dataset")
        self._format_name = format_name
        self._samples = samples or [
            {
                "sample_id": f"sample_{i}",
                "image_path": f"images/img_{i}.jpg",
                "label": i % 2,
                "class_name": f"class_{i % 2}",
            }
            for i in range(5)
        ]
        self._classes = class_names or ["class_0", "class_1"]

    @property
    def format_name(self) -> str:
        return self._format_name

    @property
    def sample_count(self) -> int:
        return len(self._samples)

    @property
    def class_names(self) -> List[str]:
        return self._classes

    def validate(self) -> ValidationResult:
        return ValidationResult(
            is_valid=True,
            format_detected=self.format_name,
            total_samples=self.sample_count,
            errors=[],
            warnings=[],
            stats={"classes": len(self.class_names)},
        )

    def get_sample(self, index: int) -> Dict[str, Any]:
        if not (0 <= index < len(self._samples)):
            raise IndexError(f"Index {index} out of range for mock dataset (size {len(self._samples)})")
        return self._samples[index]
