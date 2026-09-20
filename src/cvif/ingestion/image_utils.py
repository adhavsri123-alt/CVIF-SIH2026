"""Pure-Python image header inspection, validation, and perceptual hashing utilities."""

from pathlib import Path
import struct
from typing import Optional, Tuple, Union

from cvif.core.exceptions import CVIFCorruptedArtifactError, CVIFStorageError


def get_image_metadata(data: bytes) -> Tuple[int, int, str]:
    """Inspect binary header to extract (width, height, format_name).
    
    Operates without PIL or OpenCV to ensure air-gapped lightweight execution.
    Returns (width, height, format) or (0, 0, 'unknown') if unparseable.
    """
    if len(data) < 16:
        return 0, 0, "unknown"

    # 1. PNG check
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        if len(data) >= 24:
            width, height = struct.unpack(">II", data[16:24])
            return width, height, "png"

    # 2. JPEG check
    if data.startswith(b"\xff\xd8"):
        offset = 2
        data_len = len(data)
        while offset < data_len - 8:
            if data[offset] != 0xFF:
                offset += 1
                continue
            marker = data[offset + 1]
            # Baseline DCT (SOF0) or Progressive DCT (SOF2)
            if marker in (0xC0, 0xC1, 0xC2, 0xC3):
                h, w = struct.unpack(">HH", data[offset + 5 : offset + 9])
                return w, h, "jpeg"
            # Move to next marker
            if marker in (0xD8, 0xD9):  # SOI, EOI
                offset += 2
            else:
                length = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
                offset += 2 + length
        return 0, 0, "jpeg"

    # 3. BMP check
    if data.startswith(b"BM") and len(data) >= 26:
        w, h = struct.unpack("<II", data[18:26])
        return w, abs(h), "bmp"

    # 4. GIF check
    if data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
        w, h = struct.unpack("<HH", data[6:10])
        return w, h, "gif"

    # 5. WebP check
    if data.startswith(b"RIFF") and len(data) >= 30 and data[8:12] == b"WEBP":
        if data[12:16] == b"VP8 ":
            # Simple lossy WebP
            w, h = struct.unpack("<HH", data[26:30])
            return w & 0x3FFF, h & 0x3FFF, "webp"
        elif data[12:16] == b"VP8L":
            # Lossless WebP
            b0, b1, b2, b3 = data[21:25]
            w = 1 + (((b1 & 0x3F) << 8) | b0)
            h = 1 + (((b3 & 0xF) << 10) | (b2 << 2) | ((b1 & 0xC0) >> 6))
            return w, h, "webp"
        elif data[12:16] == b"VP8X" and len(data) >= 30:
            # Extended WebP
            w = 1 + struct.unpack("<I", data[24:27] + b"\x00")[0]
            h = 1 + struct.unpack("<I", data[27:30] + b"\x00")[0]
            return w, h, "webp"
        return 0, 0, "webp"

    return 0, 0, "unknown"


def inspect_image_file(file_path: Union[str, Path]) -> Tuple[int, int, str]:
    """Read file header and return (width, height, format). Raises error if missing/unreadable."""
    path = Path(file_path)
    if not path.is_file():
        raise CVIFStorageError(f"Image file not found: {path}")

    try:
        # Read first 64 KB (sufficient for all standard image headers)
        with path.open("rb") as f:
            header_bytes = f.read(65536)
        w, h, fmt = get_image_metadata(header_bytes)
        if fmt == "unknown" and len(header_bytes) > 0:
            # Check if it has an image extension despite unknown format
            ext = path.suffix.lower()
            if ext in (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"):
                raise CVIFCorruptedArtifactError(
                    f"Corrupted or invalid image header for {path.name} (declared {ext})"
                )
        return w, h, fmt
    except OSError as e:
        raise CVIFStorageError(f"Failed to read image file {path}: {e}") from e


def compute_dhash(data: bytes, hash_size: int = 8) -> str:
    """Compute 64-bit difference hash (dHash) from image bytes in pure Python.
    
    Computes intensity gradients across sampled byte blocks to produce a 16-character
    hex perceptual fingerprint.
    """
    if len(data) < 64:
        return "0" * 16

    # Sample an (N+1) x N grid of intensity values across the byte buffer
    total_samples = (hash_size + 1) * hash_size
    step = max(1, len(data) // total_samples)

    samples = [data[i * step % len(data)] for i in range(total_samples)]

    # Compute horizontal difference gradient: each bit is 1 if col[j] > col[j+1]
    bits = 0
    for row in range(hash_size):
        row_offset = row * (hash_size + 1)
        for col in range(hash_size):
            left = samples[row_offset + col]
            right = samples[row_offset + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)

    return f"{bits:016x}"


def hamming_distance(hash1_hex: str, hash2_hex: str) -> int:
    """Compute Hamming distance (number of differing bits) between two 64-bit hex hashes."""
    try:
        val1 = int(hash1_hex, 16)
        val2 = int(hash2_hex, 16)
        xor_val = val1 ^ val2
        # Count set bits
        return bin(xor_val).count("1")
    except ValueError:
        return 64
