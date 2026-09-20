"""Automatic format detection for computer vision training and evaluation datasets."""

import json
from pathlib import Path
from typing import Optional, Tuple, Union

from cvif.core.exceptions import CVIFStorageError


class FormatDetector:
    """Detects dataset format (COCO vs YOLO) by inspecting filesystem hierarchy and manifests."""

    @staticmethod
    def detect(dataset_path: Union[str, Path]) -> Tuple[str, str]:
        """Inspect directory and return (format_name, variant_details).
        
        Returns:
            ("coco", variant_str) if COCO structure detected
            ("yolo", variant_str) if YOLO structure detected
            ("unsupported", reason) if unrecognized
        """
        path = Path(dataset_path).resolve()
        if not path.exists():
            raise CVIFStorageError(f"Dataset path does not exist: {path}")
        if not path.is_dir():
            raise CVIFStorageError(f"Dataset path is not a directory: {path}")

        # 1. Check for data.yaml (definitive YOLO marker)
        for yaml_name in ("data.yaml", "data.yml", "dataset.yaml", "dataset.yml"):
            if (path / yaml_name).is_file():
                return "yolo", "yolo_yaml_configured"

        # 2. Check for COCO JSON annotations
        ann_candidates = [
            path / "annotations" / "instances_train.json",
            path / "annotations" / "instances_val.json",
            path / "instances_train.json",
            path / "instances_val.json",
        ]
        for candidate in ann_candidates:
            if candidate.is_file() and FormatDetector._is_coco_json(candidate):
                return "coco", "coco_standard"

        # Check split-first directories: train/, valid/, val/, test/
        for split in ("train", "valid", "val", "test"):
            split_dir = path / split
            if split_dir.is_dir():
                split_candidates = [
                    split_dir / "_annotations.coco.json",
                    split_dir / "annotations.json",
                    split_dir / "instances.json",
                    split_dir / f"instances_{split}.json",
                ]
                for sc in split_candidates:
                    if sc.is_file() and FormatDetector._is_coco_json(sc):
                        return "coco", "coco_split_first"

                for json_file in sorted(split_dir.glob("*.json")):
                    if FormatDetector._is_coco_json(json_file):
                        return "coco", "coco_split_first"

        # Check any JSON in annotations/ or root
        ann_dir = path / "annotations"
        if ann_dir.is_dir():
            for json_file in sorted(ann_dir.glob("*.json")):
                if FormatDetector._is_coco_json(json_file):
                    return "coco", "coco_json"

        for json_file in sorted(path.glob("*.json")):
            if FormatDetector._is_coco_json(json_file):
                return "coco", "coco_root_json"

        # 3. Check for YOLO directory layouts (images/ and labels/)
        images_dir = path / "images"
        labels_dir = path / "labels"
        if images_dir.is_dir() and labels_dir.is_dir():
            subdirs = [d.name for d in images_dir.iterdir() if d.is_dir()]
            if any(s in ("train", "val", "test") for s in subdirs):
                return "yolo", "yolo_split"
            return "yolo", "yolo_flat"

        # 4. Check for direct paired layout (.txt next to images)
        txt_files = list(path.glob("**/*.txt"))
        if txt_files:
            # Check if text file looks like YOLO row: int float float float float
            for txt_file in txt_files[:5]:
                try:
                    lines = txt_file.read_text(encoding="utf-8").splitlines()
                    for line in lines:
                        parts = line.strip().split()
                        if len(parts) >= 5:
                            # Verify first is int, remainder are floats
                            int(parts[0])
                            float(parts[1])
                            float(parts[2])
                            return "yolo", "yolo_paired_txt"
                except Exception:
                    continue

        return "unsupported", "No recognizable COCO or YOLO format markers found"

    @staticmethod
    def _is_coco_json(file_path: Path) -> bool:
        """Lightweight check for top-level COCO keys: images, annotations, categories."""
        try:
            with file_path.open("r", encoding="utf-8") as f:
                # Read first 8 KB to check keys without loading multi-hundred-megabyte JSON into RAM
                chunk = f.read(8192)
                if '"images"' in chunk and ('"annotations"' in chunk or '"categories"' in chunk):
                    return True
            # If keys were later in the file, load full JSON
            with file_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
                return (
                    isinstance(data, dict)
                    and "images" in data
                    and ("annotations" in data or "categories" in data)
                )
        except Exception:
            return False
