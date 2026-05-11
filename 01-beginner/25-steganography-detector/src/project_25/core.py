"""Steganography detection in images via LSB analysis and appended-data checks."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from PIL import Image

log = logging.getLogger(__name__)

RISK_HIGH_THRESHOLD: int = 60
RISK_MEDIUM_THRESHOLD: int = 30
LSB_SUSPICIOUS_THRESHOLD: float = 0.47
LSB_SAMPLE_PIXELS: int = 10_000
MIN_SUSPICIOUS_EXIF_BYTES: int = 4_096
PNG_IEND_MARKER: bytes = b'IEND\xaeB`\x82'
JPEG_END_MARKER: bytes = b'\xff\xd9'
APPENDED_DATA_TOLERANCE: int = 512


@dataclass(frozen=True)
class StegoResult:
    """Steganography analysis result for an image file."""

    path: str
    file_size: int
    image_format: str
    dimensions: tuple[int, int] | None
    lsb_ratio: float | None
    exif_size: int
    has_appended_data: bool
    risk_score: int
    risk_level: str
    indicators: tuple[str, ...]


def analyze_image(path: str) -> StegoResult:
    """Analyse *path* for steganographic content indicators.

    Args:
        path: Path to the image file to analyse.

    Returns:
        StegoResult with risk score and detected indicators.

    Raises:
        FileNotFoundError: If *path* does not exist.
        OSError: On file read errors.
        ValueError: If the file is not a recognised image format.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path!r}")
    file_size = os.path.getsize(path)
    try:
        img = Image.open(path)
        img.load()
    except Exception as exc:
        raise ValueError(f"Cannot open image {path!r}: {exc}") from exc
    fmt = img.format or "UNKNOWN"
    dims: tuple[int, int] | None = img.size
    lsb = _compute_lsb_ratio(img)
    exif_size = _get_exif_size(img)
    appended = _check_appended_data(path, fmt)
    score, indicators, level = _compute_risk(lsb, appended, exif_size)
    return StegoResult(
        path=path, file_size=file_size, image_format=fmt, dimensions=dims,
        lsb_ratio=lsb, exif_size=exif_size, has_appended_data=appended,
        risk_score=score, risk_level=level, indicators=tuple(indicators),
    )


def _compute_lsb_ratio(img: Image.Image) -> float | None:
    try:
        rgb = img.convert("RGB")
        pixels = list(rgb.getdata())[:LSB_SAMPLE_PIXELS]
        bits = [ch & 1 for px in pixels for ch in px]
        return sum(bits) / len(bits) if bits else None
    except Exception:
        return None


def _get_exif_size(img: Image.Image) -> int:
    try:
        exif = img.getexif()
        return len(str(exif)) if exif else 0
    except Exception:
        return 0


def _check_appended_data(path: str, fmt: str) -> bool:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        if fmt == "PNG":
            idx = data.rfind(PNG_IEND_MARKER)
            return idx != -1 and len(data) > idx + len(PNG_IEND_MARKER) + APPENDED_DATA_TOLERANCE
        if fmt in ("JPEG", "MPO"):
            idx = data.rfind(JPEG_END_MARKER)
            return idx != -1 and len(data) > idx + len(JPEG_END_MARKER) + APPENDED_DATA_TOLERANCE
    except OSError:
        pass
    return False


def _compute_risk(
    lsb_ratio: float | None,
    appended: bool,
    exif_size: int,
) -> tuple[int, list[str], str]:
    score = 0
    indicators: list[str] = []
    if lsb_ratio is not None and abs(lsb_ratio - 0.5) < (0.5 - LSB_SUSPICIOUS_THRESHOLD):
        score += 40
        indicators.append(f"LSB ratio near 0.5: {lsb_ratio:.3f} (uniform bit distribution)")
    if appended:
        score += 45
        indicators.append("data found after image end marker")
    if exif_size > MIN_SUSPICIOUS_EXIF_BYTES:
        score += 15
        indicators.append(f"large EXIF block: {exif_size} bytes")
    level = _score_to_level(score)
    return score, indicators, level


def _score_to_level(score: int) -> str:
    if score >= RISK_HIGH_THRESHOLD:
        return "HIGH"
    if score >= RISK_MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"
