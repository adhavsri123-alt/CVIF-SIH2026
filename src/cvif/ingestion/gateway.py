"""Ingestion gateway orchestrating format detection, validation, registration, and audit logging."""

from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union
from uuid import uuid4

from cvif.audit.logger import AuditLogger
from cvif.core.enums import AssetStatus, AssetType, AuditEventType
from cvif.core.exceptions import CVIFFormatError, CVIFStorageError
from cvif.core.schemas import (
    AssetFileManifestEntry,
    AssetRegistration,
    HashManifest,
    UnifiedDataset,
    ValidationResult,
    utc_now,
)
from cvif.ingestion.adapters.base import DatasetAdapter
from cvif.ingestion.adapters.coco import COCOAdapter
from cvif.ingestion.adapters.yolo import YOLOAdapter
from cvif.ingestion.format_detector import FormatDetector
from cvif.storage.database import DatabaseManager
from cvif.storage.filestore import safe_resolve_path


class IngestionGateway:
    """Entry gateway for ingesting, validating, and cataloging computer vision datasets."""

    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        db_manager: Optional[DatabaseManager] = None,
    ):
        self.audit_logger = audit_logger
        self.db_manager = db_manager

    def ingest_dataset(
        self,
        dataset_path: Union[str, Path],
        contributor_id: Optional[str] = None,
        batch_id: Optional[str] = None,
        compute_hashes: bool = True,
    ) -> Tuple[UnifiedDataset, ValidationResult, AssetRegistration]:
        """Ingest a dataset from disk, validate structure, compute hashes, and record audit trail."""
        path = Path(dataset_path).resolve()
        if not path.is_dir():
            raise CVIFStorageError(f"Dataset path does not exist or is not a directory: {path}")

        # 1. Detect format
        fmt, variant = FormatDetector.detect(path)
        if fmt == "unsupported":
            raise CVIFFormatError(f"Unsupported dataset format at {path}: {variant}")

        # 2. Select adapter
        adapter: DatasetAdapter
        if fmt == "coco":
            adapter = COCOAdapter(path)
        elif fmt == "yolo":
            adapter = YOLOAdapter(path)
        else:
            raise CVIFFormatError(f"Unimplemented format adapter: {fmt}")

        # 3. Validate structure
        val_result = adapter.validate()
        if not val_result.is_valid:
            error_msg = "; ".join(val_result.errors[:5])
            raise CVIFFormatError(f"Dataset validation failed: {error_msg}")

        # 4. Load into Unified representation
        unified: UnifiedDataset = adapter.load(compute_hashes=compute_hashes)

        # 5. Attach contributor/batch provenance if explicitly provided (never invent)
        if contributor_id and not unified.contributor_id:
            unified.contributor_id = contributor_id
        if batch_id and not unified.batch_id:
            unified.batch_id = batch_id

        # Re-compute dataset hash if metadata changed
        if contributor_id or batch_id:
            unified.dataset_hash = unified.compute_dataset_hash()

        # 6. Build cryptographic HashManifest
        manifest_entries = [
            AssetFileManifestEntry(
                path=img.file_path,
                digest=img.file_hash,
                size_bytes=img.file_size_bytes,
            )
            for img in unified.images
        ]
        manifest = HashManifest(algorithm="sha256", entries=manifest_entries)

        # 7. Create AssetRegistration
        total_size = sum(img.file_size_bytes for img in unified.images)
        asset_reg = AssetRegistration(
            asset_id=unified.asset_id,
            asset_type=AssetType.DATASET,
            format=fmt,
            file_paths=[img.file_path for img in unified.images],
            hash_manifest=manifest,
            total_size_bytes=total_size,
            ingestion_timestamp=utc_now(),
            contributor_id=unified.contributor_id,
            batch_id=unified.batch_id,
            metadata={
                "variant": variant,
                "dataset_hash": unified.dataset_hash,
                "total_images": len(unified.images),
                "total_annotations": len(unified.annotations),
                "classes": [c.model_dump() for c in unified.classes],
            },
            status=AssetStatus.REGISTERED,
        )

        # 8. Persist in database if available
        if self.db_manager:
            self.db_manager.save_asset(asset_reg)

        # 9. Log audit event
        if self.audit_logger:
            self.audit_logger.log_event(
                event_type=AuditEventType.ASSET_INGESTED,
                actor="ingestion_gateway",
                asset_id=unified.asset_id,
                details={
                    "format": fmt,
                    "variant": variant,
                    "dataset_hash": unified.dataset_hash,
                    "images": len(unified.images),
                    "annotations": len(unified.annotations),
                    "classes": len(unified.classes),
                    "contributor_id": unified.contributor_id,
                },
            )

        return unified, val_result, asset_reg
