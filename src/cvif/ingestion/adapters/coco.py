"""COCO format dataset adapter for CVIF ingestion."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from uuid import uuid4

from cvif.core.exceptions import CVIFFormatError, CVIFStorageError, PathTraversalError
from cvif.core.schemas import (
    AnnotationRecord,
    ClassInfo,
    ImageRecord,
    UnifiedDataset,
    ValidationResult,
)
from cvif.crypto.hashing import sha256_file
from cvif.ingestion.adapters.base import DatasetAdapter
from cvif.ingestion.format_detector import FormatDetector
from cvif.ingestion.image_utils import inspect_image_file
from cvif.storage.filestore import safe_resolve_path


class COCOAdapter(DatasetAdapter):
    """Adapter for ingesting and validating COCO format object detection datasets."""

    def __init__(
        self,
        dataset_path: Union[str, Path],
        annotation_file: Optional[Union[str, Path]] = None,
    ):
        super().__init__(dataset_path)
        self.root_path = Path(dataset_path).resolve()
        if annotation_file:
            ann_p = Path(annotation_file).resolve()
            split = self._infer_split_from_path(ann_p)
            self.split_manifests: List[Tuple[Optional[str], Path]] = [(split, ann_p)]
            self.annotation_file: Optional[Path] = ann_p
        else:
            self.split_manifests = self._discover_manifests()
            self.annotation_file = self.split_manifests[0][1] if self.split_manifests else None

        self._cached_dataset: Optional[UnifiedDataset] = None
        self._cached_validation: Optional[ValidationResult] = None

    @property
    def format_name(self) -> str:
        return "coco"

    @property
    def sample_count(self) -> int:
        if self._cached_dataset:
            return len(self._cached_dataset.images)
        val = self.validate()
        return val.total_samples

    @property
    def class_names(self) -> List[str]:
        if self._cached_dataset:
            return [c.class_name for c in self._cached_dataset.classes]
        return []

    def _infer_split_from_path(self, path: Path) -> Optional[str]:
        """Infer canonical split name from manifest path."""
        parent_name = path.parent.name.lower()
        if parent_name in ("train", "valid", "val", "test"):
            return parent_name
        stem = path.stem.lower()
        for s in ("train", "valid", "val", "test"):
            if s in stem:
                return s
        return None

    def _discover_manifests(self) -> List[Tuple[Optional[str], Path]]:
        """Discover all COCO annotation JSON manifests in standard locations.
        
        Returns:
            List of (split_name, annotation_file_path) tuples.
        """
        if not self.root_path.is_dir():
            return []

        manifests: List[Tuple[Optional[str], Path]] = []
        discovered_paths: Set[Path] = set()

        # 1. Check split-first directories: train/, valid/, val/, test/
        for split in ("train", "valid", "val", "test"):
            split_dir = self.root_path / split
            if split_dir.is_dir():
                candidates = [
                    split_dir / "_annotations.coco.json",
                    split_dir / f"instances_{split}.json",
                    split_dir / "instances.json",
                    split_dir / "annotations.json",
                ]
                found = False
                for c in candidates:
                    if c.is_file() and FormatDetector._is_coco_json(c):
                        manifests.append((split, c))
                        discovered_paths.add(c.resolve())
                        found = True
                        break
                if not found:
                    for jf in sorted(split_dir.glob("*.json")):
                        if jf.resolve() not in discovered_paths and FormatDetector._is_coco_json(jf):
                            manifests.append((split, jf))
                            discovered_paths.add(jf.resolve())
                            break

        if manifests:
            return manifests

        # 2. Check annotations/ directory
        ann_dir = self.root_path / "annotations"
        if ann_dir.is_dir():
            std_ann = [
                ("train", ann_dir / "instances_train.json"),
                ("val", ann_dir / "instances_val.json"),
                ("valid", ann_dir / "instances_valid.json"),
                ("test", ann_dir / "instances_test.json"),
            ]
            found_std = False
            for split, c in std_ann:
                if c.is_file() and c.resolve() not in discovered_paths and FormatDetector._is_coco_json(c):
                    manifests.append((split, c))
                    discovered_paths.add(c.resolve())
                    found_std = True
            if not found_std:
                for jf in sorted(ann_dir.glob("*.json")):
                    if jf.resolve() not in discovered_paths and FormatDetector._is_coco_json(jf):
                        s = self._infer_split_from_path(jf)
                        manifests.append((s, jf))
                        discovered_paths.add(jf.resolve())

        if manifests:
            return manifests

        # 3. Check root directory
        std_root = [
            ("train", self.root_path / "instances_train.json"),
            ("val", self.root_path / "instances_val.json"),
            ("valid", self.root_path / "instances_valid.json"),
            ("test", self.root_path / "instances_test.json"),
        ]
        found_root_std = False
        for split, c in std_root:
            if c.is_file() and c.resolve() not in discovered_paths and FormatDetector._is_coco_json(c):
                manifests.append((split, c))
                discovered_paths.add(c.resolve())
                found_root_std = True

        if not manifests:
            for jf in sorted(self.root_path.glob("*.json")):
                if jf.resolve() not in discovered_paths and FormatDetector._is_coco_json(jf):
                    s = self._infer_split_from_path(jf)
                    manifests.append((s, jf))
                    discovered_paths.add(jf.resolve())

        return manifests

    def _find_annotation_file(self) -> Path:
        """Locate primary COCO JSON annotation file within dataset directory."""
        if self.split_manifests:
            return self.split_manifests[0][1]
        manifests = self._discover_manifests()
        if manifests:
            return manifests[0][1]
        raise CVIFFormatError(
            f"No COCO annotation JSON file found in {self.root_path} (looked in root, 'annotations/', and split folders)"
        )

    def _find_image_file(self, file_name: str, preferred_dir: Optional[Path] = None) -> Optional[Path]:
        """Locate image file within standard COCO image locations."""
        # 1. If preferred_dir is given (e.g. split folder), resolve directly
        if preferred_dir and preferred_dir.is_dir():
            try:
                candidate = safe_resolve_path(preferred_dir, file_name)
                if candidate.is_file():
                    return candidate
            except (PathTraversalError, CVIFStorageError):
                pass

        # 2. Sanitize against path traversal in file_name relative to root_path
        try:
            target = safe_resolve_path(self.root_path, file_name)
            if target.is_file():
                return target
        except PathTraversalError:
            return None

        # 3. Check standard subdirectories: images/, train/, valid/, val/, test/, etc.
        candidate_subs = (
            "images",
            "train",
            "valid",
            "val",
            "test",
            "images/train",
            "images/valid",
            "images/val",
            "images/test",
        )
        for sub in candidate_subs:
            try:
                candidate = safe_resolve_path(self.root_path / sub, file_name)
                if candidate.is_file():
                    return candidate
            except (PathTraversalError, CVIFStorageError):
                continue

        # 4. Fallback search by basename across all images
        target_name = Path(file_name).name
        for match in self.root_path.glob(f"**/{target_name}"):
            try:
                resolved = safe_resolve_path(self.root_path, match)
                if resolved.is_file():
                    return resolved
            except (PathTraversalError, CVIFStorageError):
                continue

        return None

    def validate(self) -> ValidationResult:
        """Perform non-destructive structural validation of COCO format integrity across all manifests."""
        errors: List[str] = []
        warnings: List[str] = []

        if not self.root_path.exists():
            return ValidationResult(
                is_valid=False,
                format_detected="coco",
                total_samples=0,
                errors=[f"Dataset root path does not exist: {self.root_path}"],
                warnings=[],
                stats={},
            )

        if not self.split_manifests:
            return ValidationResult(
                is_valid=False,
                format_detected="coco",
                total_samples=0,
                errors=[f"No COCO annotation JSON file found in {self.root_path}"],
                warnings=[],
                stats={},
            )

        is_multi_split = (
            len(self.split_manifests) > 1
            or any(
                split is not None and (self.root_path / split).is_dir()
                for split, _ in self.split_manifests
            )
        )

        global_image_ids: Set[str] = set()
        global_cat_ids: Dict[int, str] = {}
        annotated_image_ids: Set[str] = set()

        total_images_declared = 0
        verified_images = 0
        missing_images = 0
        total_annotations = 0
        orphan_annotations = 0
        invalid_bboxes = 0
        manifest_splits: List[str] = []

        for split_name, manifest_path in self.split_manifests:
            if not manifest_path or not manifest_path.is_file():
                errors.append(f"Annotation file not found: {manifest_path}")
                continue

            if split_name:
                manifest_splits.append(split_name)

            try:
                with manifest_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:
                errors.append(f"Malformed JSON in annotation file {manifest_path.name}: {e}")
                continue

            # Verify mandatory top-level keys
            missing_keys = [k for k in ("images", "annotations", "categories") if k not in data]
            if missing_keys:
                errors.append(
                    f"Missing mandatory COCO top-level key(s) in {manifest_path.name}: {', '.join(missing_keys)}"
                )
                continue

            raw_images = data.get("images", [])
            raw_annotations = data.get("annotations", [])
            raw_categories = data.get("categories", [])

            total_images_declared += len(raw_images)
            total_annotations += len(raw_annotations)

            # Category validation
            manifest_cat_ids: Set[int] = set()
            for cat in raw_categories:
                if not isinstance(cat, dict) or "id" not in cat or "name" not in cat:
                    errors.append(f"Malformed category entry missing 'id' or 'name' in {manifest_path.name}: {cat}")
                else:
                    c_id = cat["id"]
                    c_name = cat["name"]
                    manifest_cat_ids.add(c_id)
                    if c_id in global_cat_ids and global_cat_ids[c_id] != c_name:
                        warnings.append(
                            f"Category ID {c_id} has conflicting names across manifests: "
                            f"'{global_cat_ids[c_id]}' vs '{c_name}' in {manifest_path.name}"
                        )
                    global_cat_ids[c_id] = c_name

            # Image ID validation & file check
            split_image_ids: Set[str] = set()
            preferred_dir = manifest_path.parent

            for img in raw_images:
                raw_img_id = img.get("id")
                if raw_img_id is None or str(raw_img_id) == "None":
                    errors.append(f"Image entry missing valid 'id' in {manifest_path.name}: {img}")
                    continue

                if is_multi_split and split_name:
                    img_id = f"{split_name}_{raw_img_id}"
                else:
                    img_id = str(raw_img_id)

                if img_id in global_image_ids:
                    errors.append(f"Duplicate image id in COCO manifest: '{img_id}'")
                global_image_ids.add(img_id)
                split_image_ids.add(img_id)

                file_name = img.get("file_name")
                if not file_name:
                    errors.append(f"Image id '{img_id}' missing 'file_name' in {manifest_path.name}")
                    continue

                found_file = self._find_image_file(file_name, preferred_dir=preferred_dir)
                if not found_file:
                    missing_images += 1
                    errors.append(f"Referenced image file '{file_name}' (id={img_id}) not found on disk")
                else:
                    verified_images += 1

            # Annotation validation
            for ann in raw_annotations:
                raw_ann_id = ann.get("id")
                if is_multi_split and split_name:
                    ann_id = f"{split_name}_{raw_ann_id}"
                    img_id = f"{split_name}_{ann.get('image_id')}"
                else:
                    ann_id = str(raw_ann_id)
                    img_id = str(ann.get("image_id"))

                cat_id = ann.get("category_id")

                if img_id not in split_image_ids and img_id not in global_image_ids:
                    orphan_annotations += 1
                    errors.append(f"Orphan annotation '{ann_id}' references unknown image_id '{img_id}'")

                if cat_id not in manifest_cat_ids and cat_id not in global_cat_ids:
                    errors.append(f"Annotation '{ann_id}' references unknown category_id '{cat_id}'")

                annotated_image_ids.add(img_id)

                # Check bbox
                bbox = ann.get("bbox")
                if bbox is not None:
                    if not isinstance(bbox, list) or len(bbox) != 4:
                        invalid_bboxes += 1
                        errors.append(f"Annotation '{ann_id}' has malformed bbox (expected 4 numbers): {bbox}")
                    else:
                        x, y, w, h = bbox
                        if w <= 0 or h <= 0:
                            invalid_bboxes += 1
                            errors.append(f"Annotation '{ann_id}' has non-positive width or height: w={w}, h={h}")
                        if x < 0 or y < 0:
                            warnings.append(f"Annotation '{ann_id}' has negative coordinates: x={x}, y={y}")

                # Check segmentation if present
                seg = ann.get("segmentation")
                if seg is not None and not isinstance(seg, (list, dict)):
                    errors.append(f"Annotation '{ann_id}' has malformed segmentation structure: {type(seg)}")

        # Unannotated images warning
        unannotated = len(global_image_ids) - len(annotated_image_ids)
        if unannotated > 0:
            warnings.append(f"{unannotated} image(s) have no annotations in dataset manifest")

        # Zero-match validation failure: fail clearly rather than silently returning an apparently valid empty dataset
        if not errors and self.split_manifests:
            if total_images_declared == 0 and total_annotations == 0:
                errors.append("Annotation files exist but contain zero images and zero annotations")
            elif verified_images == 0:
                errors.append("Annotation files exist but zero valid images could be resolved on disk")

        stats = {
            "total_images": total_images_declared,
            "verified_images": verified_images,
            "missing_images": missing_images,
            "total_annotations": total_annotations,
            "total_categories": len(global_cat_ids),
            "orphan_annotations": orphan_annotations,
            "invalid_bboxes": invalid_bboxes,
            "unannotated_images": unannotated,
            "splits": manifest_splits,
        }

        is_valid = len(errors) == 0
        res = ValidationResult(
            is_valid=is_valid,
            format_detected="coco",
            total_samples=verified_images,
            errors=errors,
            warnings=warnings,
            stats=stats,
        )
        self._cached_validation = res
        return res

    def load(self, compute_hashes: bool = True) -> UnifiedDataset:
        """Parse COCO dataset into canonical UnifiedDataset representation."""
        val = self.validate()
        if not val.is_valid:
            error_summary = "; ".join(val.errors[:5])
            raise CVIFFormatError(f"Cannot load invalid COCO dataset: {error_summary}")

        is_multi_split = (
            len(self.split_manifests) > 1
            or any(
                split is not None and (self.root_path / split).is_dir()
                for split, _ in self.split_manifests
            )
        )

        all_image_records: List[ImageRecord] = []
        all_annotation_records: List[AnnotationRecord] = []
        cat_map: Dict[int, str] = {}
        class_counts: Dict[int, int] = {}
        image_dims: Dict[str, Tuple[int, int]] = {}
        splits: Dict[str, List[str]] = {}
        contributor_id: Optional[str] = None
        manifest_names: List[str] = []

        # First pass: collect categories across all manifests
        for split_name, manifest_path in self.split_manifests:
            try:
                rel_manifest = str(manifest_path.relative_to(self.root_path)).replace("\\", "/")
            except ValueError:
                rel_manifest = str(manifest_path)
            manifest_names.append(rel_manifest)

            with manifest_path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            if not contributor_id:
                info = data.get("info", {})
                contributor_id = info.get("contributor") or None

            for cat in data.get("categories", []):
                c_id = cat["id"]
                c_name = cat["name"]
                cat_map[c_id] = c_name
                if c_id not in class_counts:
                    class_counts[c_id] = 0

        # Second pass: load images and annotations per manifest
        for split_name, manifest_path in self.split_manifests:
            preferred_dir = manifest_path.parent
            with manifest_path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            raw_images = data.get("images", [])
            raw_annotations = data.get("annotations", [])

            for img in raw_images:
                raw_img_id = img["id"]
                if is_multi_split and split_name:
                    img_id = f"{split_name}_{raw_img_id}"
                else:
                    img_id = str(raw_img_id)

                file_name = img["file_name"]
                img_path = self._find_image_file(file_name, preferred_dir=preferred_dir)
                if not img_path:
                    continue

                rel_path = str(img_path.relative_to(self.root_path)).replace("\\", "/")
                f_hash = sha256_file(img_path) if compute_hashes else "0" * 64
                size_bytes = img_path.stat().st_size

                # Width and height: read from declared or header fallback
                declared_w = int(img.get("width", 0))
                declared_h = int(img.get("height", 0))
                if declared_w == 0 or declared_h == 0:
                    header_w, header_h, _ = inspect_image_file(img_path)
                    w = header_w or declared_w or 1
                    h = header_h or declared_h or 1
                else:
                    w = declared_w
                    h = declared_h

                image_dims[img_id] = (w, h)

                source_meta = img.get("source_metadata")
                if is_multi_split and split_name:
                    meta_dict = dict(source_meta) if isinstance(source_meta, dict) else {}
                    meta_dict["original_id"] = raw_img_id
                    meta_dict["split"] = split_name
                    source_meta = meta_dict

                all_image_records.append(
                    ImageRecord(
                        image_id=img_id,
                        file_path=rel_path,
                        file_hash=f_hash,
                        width=w,
                        height=h,
                        file_size_bytes=size_bytes,
                        source_metadata=source_meta,
                    )
                )

                if split_name:
                    splits.setdefault(split_name, []).append(img_id)

            for ann in raw_annotations:
                raw_ann_id = ann.get("id", uuid4())
                if is_multi_split and split_name:
                    ann_id = f"{split_name}_{raw_ann_id}"
                    img_id = f"{split_name}_{ann['image_id']}"
                else:
                    ann_id = str(raw_ann_id)
                    img_id = str(ann["image_id"])

                c_id = ann["category_id"]
                c_name = cat_map.get(c_id, f"class_{c_id}")
                class_counts[c_id] = class_counts.get(c_id, 0) + 1

                # Normalize bounding box from COCO [x, y, w, h] to [x_min, y_min, x_max, y_max] in [0, 1]
                bbox = ann.get("bbox")
                norm_bbox: Optional[List[float]] = None
                if bbox and len(bbox) == 4:
                    img_w, img_h = image_dims.get(img_id, (1, 1))
                    x, y, w, h = bbox
                    x_min = max(0.0, min(1.0, x / img_w))
                    y_min = max(0.0, min(1.0, y / img_h))
                    x_max = max(0.0, min(1.0, (x + w) / img_w))
                    y_max = max(0.0, min(1.0, (y + h) / img_h))
                    if x_max >= x_min and y_max >= y_min:
                        norm_bbox = [x_min, y_min, x_max, y_max]

                all_annotation_records.append(
                    AnnotationRecord(
                        annotation_id=ann_id,
                        image_id=img_id,
                        class_id=c_id,
                        class_name=c_name,
                        bbox=norm_bbox,
                        area=float(ann.get("area", 0.0)) if ann.get("area") is not None else None,
                        confidence=float(ann.get("score", 1.0)) if "score" in ann else None,
                        iscrowd=int(ann.get("iscrowd", 0)),
                        segmentation=ann.get("segmentation"),
                    )
                )

        classes = [
            ClassInfo(class_id=cid, class_name=cname, count=class_counts.get(cid, 0))
            for cid, cname in sorted(cat_map.items())
        ]

        unified = UnifiedDataset(
            dataset_root=str(self.root_path),
            format_origin="coco",
            images=all_image_records,
            classes=classes,
            annotations=all_annotation_records,
            splits=splits or None,
            contributor_id=contributor_id,
            metadata={
                "annotation_files": manifest_names,
                "annotation_file": str(self.annotation_file.name) if self.annotation_file else "",
                "splits": list(splits.keys()),
            },
        )
        unified.dataset_hash = unified.compute_dataset_hash()
        self._cached_dataset = unified
        return unified

    def get_sample(self, index: int) -> Dict[str, Any]:
        """Fetch sample item by index."""
        if not self._cached_dataset:
            self.load()
        assert self._cached_dataset is not None
        if not (0 <= index < len(self._cached_dataset.images)):
            raise IndexError(f"Sample index {index} out of range (size {len(self._cached_dataset.images)})")

        img = self._cached_dataset.images[index]
        anns = [a for a in self._cached_dataset.annotations if a.image_id == img.image_id]
        return {
            "sample_id": img.image_id,
            "image": img,
            "annotations": anns,
        }
