"""YOLO format dataset adapter supporting standard split, flat, and paired layouts."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from uuid import uuid4
import yaml

from cvif.core.exceptions import CVIFFormatError, CVIFStorageError
from cvif.core.schemas import (
    AnnotationRecord,
    ClassInfo,
    ImageRecord,
    UnifiedDataset,
    ValidationResult,
)
from cvif.crypto.hashing import sha256_file
from cvif.ingestion.adapters.base import DatasetAdapter
from cvif.ingestion.image_utils import inspect_image_file


IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}


class YOLOAdapter(DatasetAdapter):
    """Adapter for ingesting and validating YOLOv5/v7/v8/v9/11 object detection datasets."""

    def __init__(self, dataset_path: Union[str, Path], data_yaml_path: Optional[Union[str, Path]] = None):
        super().__init__(dataset_path)
        self.root_path = Path(dataset_path).resolve()
        self.data_yaml_path = Path(data_yaml_path).resolve() if data_yaml_path else self._find_data_yaml()
        self._cached_dataset: Optional[UnifiedDataset] = None
        self._cached_validation: Optional[ValidationResult] = None

    @property
    def format_name(self) -> str:
        return "yolo"

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

    def _find_data_yaml(self) -> Optional[Path]:
        """Locate data.yaml or dataset.yaml if present."""
        if not self.root_path.is_dir():
            return None
        for name in ("data.yaml", "data.yml", "dataset.yaml", "dataset.yml"):
            candidate = self.root_path / name
            if candidate.is_file():
                return candidate
        return None

    def _parse_data_yaml(self) -> Tuple[Dict[int, str], Optional[str], Dict[str, Any]]:
        """Extract class names, optional contributor provenance, and raw config from data.yaml."""
        if not self.data_yaml_path or not self.data_yaml_path.is_file():
            return {}, None, {}

        try:
            with self.data_yaml_path.open("r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            return {}, None, {}

        # Parse class names
        class_map: Dict[int, str] = {}
        names = cfg.get("names")
        if isinstance(names, list):
            for i, name in enumerate(names):
                class_map[i] = str(name)
        elif isinstance(names, dict):
            for k, v in names.items():
                try:
                    class_map[int(k)] = str(v)
                except ValueError:
                    continue

        contributor_id = cfg.get("contributor_id") or cfg.get("contributor") or None
        return class_map, contributor_id, cfg

    def _discover_image_label_pairs(self) -> List[Tuple[Path, Optional[Path], Optional[str]]]:
        """Discover image files and their matching label files across supported YOLO directory layouts.
        
        Returns list of (image_path, label_path_or_none, split_name).
        """
        pairs: List[Tuple[Path, Optional[Path], Optional[str]]] = []

        # 1. Check Standard Split layout: images/{train,val,test} and labels/{train,val,test}
        images_dir = self.root_path / "images"
        labels_dir = self.root_path / "labels"

        if images_dir.is_dir():
            # Check for subdirectories in images
            subdirs = [d for d in images_dir.iterdir() if d.is_dir()]
            if subdirs:
                for split_dir in subdirs:
                    split_name = split_dir.name
                    matching_label_dir = labels_dir / split_name if labels_dir.is_dir() else None
                    for img_file in sorted(split_dir.iterdir()):
                        if img_file.suffix.lower() in IMAGE_EXTENSIONS:
                            lbl_file: Optional[Path] = None
                            if matching_label_dir and matching_label_dir.is_dir():
                                candidate = matching_label_dir / f"{img_file.stem}.txt"
                                if candidate.is_file():
                                    lbl_file = candidate
                            pairs.append((img_file, lbl_file, split_name))
                if pairs:
                    return pairs

            # 2. Check Flat layout: images/ and labels/
            if labels_dir.is_dir():
                for img_file in sorted(images_dir.iterdir()):
                    if img_file.suffix.lower() in IMAGE_EXTENSIONS:
                        lbl_candidate = labels_dir / f"{img_file.stem}.txt"
                        lbl_file = lbl_candidate if lbl_candidate.is_file() else None
                        pairs.append((img_file, lbl_file, None))
                if pairs:
                    return pairs

        # 2. Check Split-first layout: {train,val,valid,test}/images and {train,val,valid,test}/labels
        split_dirs = [
            d for d in sorted(self.root_path.iterdir())
            if d.is_dir() and (d / "images").is_dir()
        ]
        if split_dirs:
            for split_dir in split_dirs:
                split_name = split_dir.name.lower()
                s_images = split_dir / "images"
                s_labels = split_dir / "labels"
                for img_file in sorted(s_images.iterdir()):
                    if img_file.suffix.lower() in IMAGE_EXTENSIONS:
                        lbl_file: Optional[Path] = None
                        if s_labels.is_dir():
                            candidate = s_labels / f"{img_file.stem}.txt"
                            if candidate.is_file():
                                lbl_file = candidate
                        pairs.append((img_file, lbl_file, split_name))
            if pairs:
                return pairs

        # 3. Check Direct paired layout: recursive search for images, with matching .txt in same folder
        for img_file in sorted(self.root_path.glob("**/*")):
            if img_file.is_file() and img_file.suffix.lower() in IMAGE_EXTENSIONS:
                # Check for same-directory .txt
                same_dir_txt = img_file.parent / f"{img_file.stem}.txt"
                lbl_file = same_dir_txt if same_dir_txt.is_file() else None

                # Fallback: check sibling labels directory if image is in an images directory
                if lbl_file is None:
                    parent_parts = list(img_file.parent.parts)
                    if "images" in parent_parts:
                        idx = len(parent_parts) - 1 - parent_parts[::-1].index("images")
                        parent_parts[idx] = "labels"
                        label_dir = Path(*parent_parts)
                        cand = label_dir / f"{img_file.stem}.txt"
                        if cand.is_file():
                            lbl_file = cand

                # Check split from parent directory name or grandparent directory name
                parent_name = img_file.parent.name.lower()
                split = None
                if parent_name in ("train", "val", "test", "valid"):
                    split = parent_name
                elif img_file.parent.parent and img_file.parent.parent.name.lower() in ("train", "val", "test", "valid"):
                    split = img_file.parent.parent.name.lower()
                pairs.append((img_file, lbl_file, split))

        return pairs

    def validate(self) -> ValidationResult:
        """Perform non-destructive structural validation of YOLO format dataset."""
        errors: List[str] = []
        warnings: List[str] = []

        if not self.root_path.exists():
            return ValidationResult(
                is_valid=False,
                format_detected="yolo",
                total_samples=0,
                errors=[f"Dataset root path does not exist: {self.root_path}"],
                warnings=[],
                stats={},
            )

        pairs = self._discover_image_label_pairs()
        if not pairs:
            return ValidationResult(
                is_valid=False,
                format_detected="yolo",
                total_samples=0,
                errors=[f"No image files ({sorted(IMAGE_EXTENSIONS)}) found in {self.root_path}"],
                warnings=[],
                stats={},
            )

        declared_classes, _, _ = self._parse_data_yaml()
        max_declared_class = max(declared_classes.keys()) if declared_classes else None

        verified_images = 0
        missing_images = 0
        unannotated_images = 0
        malformed_lines = 0
        invalid_class_ids = 0
        invalid_bboxes = 0
        total_annotations = 0

        # Check for orphan label files (.txt without image)
        all_label_files: Set[Path] = set(self.root_path.glob("**/*.txt"))
        matched_label_files: Set[Path] = set()

        for img_path, lbl_path, _ in pairs:
            if not img_path.is_file():
                missing_images += 1
                errors.append(f"Image path missing: {img_path}")
                continue

            verified_images += 1

            if not lbl_path or not lbl_path.is_file():
                unannotated_images += 1
                continue

            matched_label_files.add(lbl_path)

            # Validate label file lines
            try:
                lines = lbl_path.read_text(encoding="utf-8").splitlines()
            except Exception as e:
                errors.append(f"Unreadable label file {lbl_path}: {e}")
                continue

            if not lines:
                unannotated_images += 1

            for line_idx, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped:
                    continue

                parts = stripped.split()
                if len(parts) < 5:
                    malformed_lines += 1
                    errors.append(
                        f"Malformed annotation in {lbl_path.name}:{line_idx}: "
                        f"expected >= 5 tokens, got {len(parts)} ('{stripped}')"
                    )
                    continue

                # Class ID check
                try:
                    class_id = int(parts[0])
                    if class_id < 0:
                        invalid_class_ids += 1
                        errors.append(f"Negative class ID {class_id} in {lbl_path.name}:{line_idx}")
                    elif max_declared_class is not None and class_id > max_declared_class:
                        warnings.append(
                            f"Class ID {class_id} in {lbl_path.name}:{line_idx} exceeds declared max ({max_declared_class})"
                        )
                except ValueError:
                    malformed_lines += 1
                    errors.append(f"Non-integer class ID in {lbl_path.name}:{line_idx}: '{parts[0]}'")
                    continue

                # Coordinate parsing (handles standard 4 bbox coords or polygon segmentations)
                try:
                    coords = [float(p) for p in parts[1:]]
                except ValueError:
                    malformed_lines += 1
                    errors.append(f"Non-numeric coordinate in {lbl_path.name}:{line_idx}")
                    continue

                if len(coords) == 4:
                    xc, yc, w, h = coords
                    if w <= 0 or h <= 0:
                        invalid_bboxes += 1
                        errors.append(f"Non-positive width/height in {lbl_path.name}:{line_idx}: w={w}, h={h}")
                    if not (0.0 <= xc <= 1.05 and 0.0 <= yc <= 1.05):
                        invalid_bboxes += 1
                        errors.append(f"Out-of-bounds center coordinates in {lbl_path.name}:{line_idx}: ({xc}, {yc})")
                elif len(coords) >= 6 and len(coords) % 2 == 0:
                    # Segmentation polygon: check points in range
                    for c in coords:
                        if not (-0.05 <= c <= 1.05):
                            warnings.append(f"Polygon point out of bounds in {lbl_path.name}:{line_idx}: {c}")

                total_annotations += 1

        # Check orphan labels (exclude data.yaml or readme txt if any)
        orphan_count = 0
        candidate_label_files: Set[Path] = set()
        for lbl_file in all_label_files:
            if lbl_file.name.lower() in ("classes.txt", "readme.txt", "requirements.txt", "readme.dataset.txt", "readme.roboflow.txt"):
                continue
            candidate_label_files.add(lbl_file)
            if lbl_file not in matched_label_files:
                orphan_count += 1
                warnings.append(f"Orphan label file with no matching image: {lbl_file.name}")

        if unannotated_images > 0:
            warnings.append(f"{unannotated_images} image(s) have missing or empty label files")

        if verified_images > 0 and len(candidate_label_files) > 0 and len(matched_label_files) == 0:
            errors.append(
                f"Found {len(candidate_label_files)} label files but none matched image directory layout"
            )

        stats = {
            "total_images": len(pairs),
            "verified_images": verified_images,
            "missing_images": missing_images,
            "unannotated_images": unannotated_images,
            "total_annotations": total_annotations,
            "orphan_labels": orphan_count,
            "malformed_lines": malformed_lines,
            "invalid_class_ids": invalid_class_ids,
            "invalid_bboxes": invalid_bboxes,
            "declared_classes": len(declared_classes),
        }

        is_valid = len(errors) == 0
        res = ValidationResult(
            is_valid=is_valid,
            format_detected="yolo",
            total_samples=verified_images,
            errors=errors,
            warnings=warnings,
            stats=stats,
        )
        self._cached_validation = res
        return res

    def load(self, compute_hashes: bool = True) -> UnifiedDataset:
        """Parse YOLO dataset into canonical UnifiedDataset representation."""
        val = self.validate()
        if not val.is_valid:
            error_summary = "; ".join(val.errors[:5])
            raise CVIFFormatError(f"Cannot load invalid YOLO dataset: {error_summary}")

        pairs = self._discover_image_label_pairs()
        declared_classes, contributor_id, raw_cfg = self._parse_data_yaml()

        observed_classes: Set[int] = set()
        class_counts: Dict[int, int] = {}
        image_records: List[ImageRecord] = []
        annotation_records: List[AnnotationRecord] = []
        splits: Dict[str, List[str]] = {}

        for img_path, lbl_path, split_name in pairs:
            if not img_path.is_file():
                continue

            img_id = img_path.stem
            rel_path = str(img_path.relative_to(self.root_path)).replace("\\", "/")
            f_hash = sha256_file(img_path) if compute_hashes else "0" * 64
            size_bytes = img_path.stat().st_size

            # Inspect header for width, height
            header_w, header_h, _ = inspect_image_file(img_path)
            w = header_w or 640
            h = header_h or 640

            image_records.append(
                ImageRecord(
                    image_id=img_id,
                    file_path=rel_path,
                    file_hash=f_hash,
                    width=w,
                    height=h,
                    file_size_bytes=size_bytes,
                )
            )

            if split_name:
                splits.setdefault(split_name, []).append(img_id)

            if not lbl_path or not lbl_path.is_file():
                continue

            try:
                lines = lbl_path.read_text(encoding="utf-8").splitlines()
            except Exception:
                continue

            for line_idx, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped:
                    continue

                parts = stripped.split()
                if len(parts) < 5:
                    continue

                try:
                    c_id = int(parts[0])
                    coords = [float(p) for p in parts[1:]]
                except ValueError:
                    continue

                observed_classes.add(c_id)
                class_counts[c_id] = class_counts.get(c_id, 0) + 1
                c_name = declared_classes.get(c_id, f"class_{c_id}")

                norm_bbox: Optional[List[float]] = None
                segmentation: Optional[Any] = None

                if len(coords) == 4:
                    # Standard bbox: center_x, center_y, width, height
                    xc, yc, bw, bh = coords
                    x_min = max(0.0, min(1.0, xc - bw / 2.0))
                    y_min = max(0.0, min(1.0, yc - bh / 2.0))
                    x_max = max(0.0, min(1.0, xc + bw / 2.0))
                    y_max = max(0.0, min(1.0, yc + bh / 2.0))
                    if x_max >= x_min and y_max >= y_min:
                        norm_bbox = [x_min, y_min, x_max, y_max]
                elif len(coords) >= 6 and len(coords) % 2 == 0:
                    # Polygon segmentation: compute bounding box envelope
                    xs = coords[0::2]
                    ys = coords[1::2]
                    x_min = max(0.0, min(1.0, min(xs)))
                    y_min = max(0.0, min(1.0, min(ys)))
                    x_max = max(0.0, min(1.0, max(xs)))
                    y_max = max(0.0, min(1.0, max(ys)))
                    if x_max >= x_min and y_max >= y_min:
                        norm_bbox = [x_min, y_min, x_max, y_max]
                    segmentation = coords

                ann_id = f"{img_id}_ann_{line_idx}"
                annotation_records.append(
                    AnnotationRecord(
                        annotation_id=ann_id,
                        image_id=img_id,
                        class_id=c_id,
                        class_name=c_name,
                        bbox=norm_bbox,
                        segmentation=segmentation,
                    )
                )

        # Build class list (combine declared and observed)
        all_class_ids = sorted(set(declared_classes.keys()) | observed_classes)
        classes = [
            ClassInfo(
                class_id=cid,
                class_name=declared_classes.get(cid, f"class_{cid}"),
                count=class_counts.get(cid, 0),
            )
            for cid in all_class_ids
        ]

        unified = UnifiedDataset(
            dataset_root=str(self.root_path),
            format_origin="yolo",
            images=image_records,
            classes=classes,
            annotations=annotation_records,
            splits=splits or None,
            contributor_id=contributor_id,
            metadata={
                "data_yaml_present": self.data_yaml_path is not None,
                "raw_config": raw_cfg,
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
