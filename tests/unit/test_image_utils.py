"""Unit tests for pure-Python image inspection, header parsing, and perceptual dHash."""

from pathlib import Path
import pytest

from cvif.core.exceptions import CVIFCorruptedArtifactError, CVIFStorageError
from cvif.ingestion.image_utils import (
    compute_dhash,
    get_image_metadata,
    hamming_distance,
    inspect_image_file,
)


def create_minimal_png(width: int = 100, height: int = 80) -> bytes:
    """Construct a syntactically valid minimal PNG byte stream with IHDR chunk."""
    import struct
    import zlib

    signature = b"\x89PNG\r\n\x1a\n"
    # IHDR chunk: width (4B), height (4B), bit_depth (1B=8), color_type (1B=2 RGB), ...
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data))
    ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + ihdr_crc

    # Minimal IDAT with 1 scanline of zeroes
    raw_scanlines = b"\x00" * (1 + width * 3)
    compressed = zlib.compress(raw_scanlines)
    idat_crc = struct.pack(">I", zlib.crc32(b"IDAT" + compressed))
    idat = struct.pack(">I", len(compressed)) + b"IDAT" + compressed + idat_crc

    # IEND chunk
    iend_crc = struct.pack(">I", zlib.crc32(b"IEND"))
    iend = struct.pack(">I", 0) + b"IEND" + iend_crc

    return signature + ihdr + idat + iend


def create_minimal_jpeg(width: int = 64, height: int = 48) -> bytes:
    """Construct a minimal JPEG header stream containing SOI and SOF0 marker."""
    import struct

    soi = b"\xff\xd8"
    # SOF0 marker (Baseline DCT)
    # length (2B = 8 + 3*components), precision (1B=8), height (2B), width (2B), components (1B=3)
    sof0_payload = struct.pack(">BHHB", 8, height, width, 3) + b"\x01\x11\x00\x02\x11\x00\x03\x11\x00"
    sof0_len = struct.pack(">H", len(sof0_payload) + 2)
    sof0 = b"\xff\xc0" + sof0_len + sof0_payload
    eoi = b"\xff\xd9"
    return soi + sof0 + eoi


def test_png_header_inspection(temp_dir: Path):
    png_bytes = create_minimal_png(width=128, height=96)
    w, h, fmt = get_image_metadata(png_bytes)
    assert w == 128
    assert h == 96
    assert fmt == "png"

    file_path = temp_dir / "sample.png"
    file_path.write_bytes(png_bytes)
    f_w, f_h, f_fmt = inspect_image_file(file_path)
    assert f_w == 128
    assert f_h == 96
    assert f_fmt == "png"


def test_jpeg_header_inspection(temp_dir: Path):
    jpeg_bytes = create_minimal_jpeg(width=320, height=240)
    w, h, fmt = get_image_metadata(jpeg_bytes)
    assert w == 320
    assert h == 240
    assert fmt == "jpeg"

    file_path = temp_dir / "sample.jpg"
    file_path.write_bytes(jpeg_bytes)
    f_w, f_h, f_fmt = inspect_image_file(file_path)
    assert f_w == 320
    assert f_h == 240
    assert f_fmt == "jpeg"


def test_corrupted_image_detection(temp_dir: Path):
    corrupt_file = temp_dir / "broken.jpg"
    corrupt_file.write_bytes(b"THIS_IS_NOT_A_JPEG_FILE_JUST_RANDOM_GARBAGE_1234567890")

    with pytest.raises(CVIFCorruptedArtifactError):
        inspect_image_file(corrupt_file)


def test_perceptual_dhash_and_hamming_distance():
    img1 = create_minimal_png(100, 100)
    h1 = compute_dhash(img1)
    assert len(h1) == 16  # 64 bits = 16 hex characters

    # Identical image produces Hamming distance 0
    assert hamming_distance(h1, h1) == 0

    # Slight byte mutation
    img2 = bytearray(img1)
    img2[len(img2) // 2] = (img2[len(img2) // 2] + 1) % 256
    h2 = compute_dhash(bytes(img2))

    # Distance should be small (near duplicate)
    dist = hamming_distance(h1, h2)
    assert dist <= 6

    # Radically different synthetic buffer
    different_bytes = bytes([i % 256 for i in range(len(img1))])
    h3 = compute_dhash(different_bytes)
    assert hamming_distance(h1, h3) > 10
