"""Reference Battery framework for deterministic offline behavioral probing and fingerprinting."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import UUID, uuid4
import zlib

from cvif.core.enums import BatteryDifficulty, ModelTask
from cvif.core.exceptions import CorruptedArtifactError, StorageError
from cvif.core.schemas import BatteryImage, DetectionOutput, ReferenceBattery
from cvif.crypto.hashing import sha256_bytes


def _make_minimal_png(width: int, height: int, r: int, g: int, b: int) -> bytes:
    """Generate minimal valid RGB PNG image in pure Python."""
    raw_scanlines = bytearray()
    row = bytearray([0]) + bytearray([r, g, b] * width)
    for _ in range(height):
        raw_scanlines.extend(row)

    compressed = zlib.compress(bytes(raw_scanlines))

    def _chunk(tag: bytes, data: bytes) -> bytes:
        import struct
        payload = tag + data
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + payload + struct.pack(">I", crc)

    import struct
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", compressed) + _chunk(b"IEND", b"")


class ReferenceBatteryBuilder:
    """Builder for constructing and persisting deterministic reference probe batteries."""

    @staticmethod
    def create_synthetic_battery(
        task_type: ModelTask = ModelTask.CLASSIFICATION,
        name: str = "standard_cvif_reference_battery",
        domain: str = "defense_surveillance",
        num_clean: int = 8,
        num_perturbed: int = 4,
        output_dir: Optional[Path] = None,
    ) -> ReferenceBattery:
        """Create a deterministic, reproducible reference battery with clean and perturbed probes."""
        images: List[BatteryImage] = []
        expected_behaviors: Dict[str, Any] = {}

        classes = ["military_vehicle", "civilian_car", "aerial_drone", "radar_station"]

        # Base color schemes for deterministic visual probes
        color_palette = [
            (50, 100, 150),
            (120, 80, 40),
            (70, 140, 60),
            (160, 50, 50),
            (90, 90, 110),
            (140, 130, 70),
            (60, 100, 80),
            (110, 60, 130),
        ]

        # 1. Clean probe generation
        for i in range(num_clean):
            img_id = f"probe_clean_{i:03d}"
            cls_idx = i % len(classes)
            label = classes[cls_idx]
            rgb = color_palette[i % len(color_palette)]
            png_bytes = _make_minimal_png(64, 64, rgb[0], rgb[1], rgb[2])
            img_hash = sha256_bytes(png_bytes)

            file_path = f"images/{img_id}.png"
            if output_dir:
                img_file = output_dir / "images" / f"{img_id}.png"
                img_file.parent.mkdir(parents=True, exist_ok=True)
                img_file.write_bytes(png_bytes)

            bboxes = None
            if task_type == ModelTask.DETECTION:
                # Deterministic bounding box in one of 4 quadrants
                q = i % 4
                x_offset = 0.1 if (q % 2 == 0) else 0.55
                y_offset = 0.1 if (q < 2) else 0.55
                bboxes = [
                    DetectionOutput(
                        bbox=[x_offset, y_offset, x_offset + 0.35, y_offset + 0.35],
                        class_id=cls_idx,
                        class_name=label,
                        confidence=1.0,
                    )
                ]

            difficulty = (
                BatteryDifficulty.EASY if i < 3
                else (BatteryDifficulty.MEDIUM if i < 6 else BatteryDifficulty.HARD)
            )

            images.append(
                BatteryImage(
                    image_id=img_id,
                    file_path=file_path,
                    file_hash=img_hash,
                    label=label,
                    difficulty=difficulty,
                    ground_truth_bboxes=bboxes,
                    perturbation_type=None,
                    metadata={"probe_type": "clean", "color": rgb},
                )
            )
            expected_behaviors[img_id] = {
                "expected_class_id": cls_idx,
                "expected_class_name": label,
                "min_expected_confidence": 0.5,
            }

        # 2. Perturbed probe generation (trigger injection / noise)
        for i in range(num_perturbed):
            img_id = f"probe_perturbed_{i:03d}"
            cls_idx = (i + 1) % len(classes)
            label = classes[cls_idx]
            rgb = (color_palette[i % len(color_palette)][0] ^ 0x33, 200, 220)
            png_bytes = _make_minimal_png(64, 64, rgb[0], rgb[1], rgb[2])
            img_hash = sha256_bytes(png_bytes)

            file_path = f"images/{img_id}.png"
            if output_dir:
                img_file = output_dir / "images" / f"{img_id}.png"
                img_file.parent.mkdir(parents=True, exist_ok=True)
                img_file.write_bytes(png_bytes)

            bboxes = None
            if task_type == ModelTask.DETECTION:
                bboxes = [
                    DetectionOutput(
                        bbox=[0.2, 0.2, 0.6, 0.6],
                        class_id=cls_idx,
                        class_name=label,
                        confidence=1.0,
                    )
                ]

            ptype = "corner_trigger_patch" if (i % 2 == 0) else "checkerboard_patch"

            images.append(
                BatteryImage(
                    image_id=img_id,
                    file_path=file_path,
                    file_hash=img_hash,
                    label=label,
                    difficulty=BatteryDifficulty.HARD,
                    ground_truth_bboxes=bboxes,
                    perturbation_type=ptype,
                    metadata={"probe_type": "perturbed", "trigger_type": ptype},
                )
            )
            expected_behaviors[img_id] = {
                "expected_class_id": cls_idx,
                "perturbation_type": ptype,
                "is_adversarial_probe": True,
            }

        battery = ReferenceBattery(
            battery_id=uuid4(),
            name=name,
            description=f"Deterministic {task_type.value} reference probe battery for {domain}",
            domain=domain,
            task_type=task_type,
            images=images,
            expected_behaviors=expected_behaviors,
            metadata={"num_clean": num_clean, "num_perturbed": num_perturbed},
        )
        battery.battery_hash = battery.compute_battery_hash()

        if output_dir:
            manifest_file = output_dir / "battery_manifest.json"
            manifest_file.parent.mkdir(parents=True, exist_ok=True)
            manifest_file.write_text(battery.to_canonical_json(), encoding="utf-8")

        return battery

    @staticmethod
    def load_battery(battery_dir: Union[str, Path]) -> ReferenceBattery:
        """Load and cryptographically verify a reference battery from a directory."""
        dir_path = Path(battery_dir).resolve()
        manifest_file = dir_path / "battery_manifest.json"
        if not manifest_file.is_file():
            raise StorageError(f"Reference battery manifest not found: {manifest_file}")

        try:
            data = json.loads(manifest_file.read_text(encoding="utf-8"))
            battery = ReferenceBattery.model_validate(data)
        except Exception as e:
            raise CorruptedArtifactError(f"Failed to parse battery manifest {manifest_file}: {e}") from e

        computed_hash = battery.compute_battery_hash()
        if battery.battery_hash and battery.battery_hash != computed_hash:
            raise CorruptedArtifactError(
                f"Battery hash mismatch: declared {battery.battery_hash} != computed {computed_hash}"
            )

        # Verify probe image files and digests
        for img in battery.images:
            img_file = dir_path / img.file_path
            if not img_file.is_file():
                raise CorruptedArtifactError(f"Missing battery probe image: {img_file}")
            actual_digest = sha256_bytes(img_file.read_bytes())
            if actual_digest != img.file_hash:
                raise CorruptedArtifactError(
                    f"Corrupted battery probe {img.image_id}: digest mismatch ({actual_digest} != {img.file_hash})"
                )

        return battery
