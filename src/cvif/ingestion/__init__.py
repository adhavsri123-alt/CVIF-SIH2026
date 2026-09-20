"""Ingestion package for CVIF computer vision datasets."""

from cvif.ingestion.adapters.base import DatasetAdapter, MockDatasetAdapter
from cvif.ingestion.adapters.coco import COCOAdapter
from cvif.ingestion.adapters.yolo import YOLOAdapter
from cvif.ingestion.format_detector import FormatDetector
from cvif.ingestion.gateway import IngestionGateway
from cvif.ingestion.image_utils import (
    compute_dhash,
    get_image_metadata,
    hamming_distance,
    inspect_image_file,
)

__all__ = [
    "DatasetAdapter",
    "MockDatasetAdapter",
    "COCOAdapter",
    "YOLOAdapter",
    "FormatDetector",
    "IngestionGateway",
    "compute_dhash",
    "get_image_metadata",
    "hamming_distance",
    "inspect_image_file",
]
