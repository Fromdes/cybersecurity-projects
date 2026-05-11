"""QR code generation for TOTP provisioning URIs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import qrcode
import qrcode.image.base
from qrcode.main import QRCode

# QR code rendering constants
QR_ERROR_CORRECTION = qrcode.constants.ERROR_CORRECT_L
QR_BOX_SIZE: int = 10
QR_BORDER: int = 4

# TOTP defaults
DEFAULT_DIGITS: int = 6
DEFAULT_INTERVAL: int = 30
DEFAULT_ISSUER: str = "DefensivePortfolio"
DEFAULT_ACCOUNT: str = "user@example.com"


@dataclass(frozen=True)
class TOTPParams:
    """Parameters needed to build an ``otpauth://`` provisioning URI."""

    secret: str
    issuer: str = DEFAULT_ISSUER
    account: str = DEFAULT_ACCOUNT
    digits: int = DEFAULT_DIGITS
    interval: int = DEFAULT_INTERVAL


def generate_uri(params: TOTPParams) -> str:
    """Build an RFC-compliant ``otpauth://totp/`` provisioning URI.

    Args:
        params: TOTP credential parameters.

    Returns:
        ``otpauth://totp/{issuer}:{account}?...`` URI string.
    """
    label = quote(f"{params.issuer}:{params.account}", safe="")
    uri = (
        f"otpauth://totp/{label}"
        f"?secret={params.secret}"
        f"&issuer={quote(params.issuer)}"
        f"&digits={params.digits}"
        f"&period={params.interval}"
        f"&algorithm=SHA1"
    )
    return uri


def render_png(uri: str, output: Path) -> None:
    """Render *uri* as a QR code PNG at *output*.

    Args:
        uri: ``otpauth://`` provisioning URI.
        output: Destination path for the PNG file.

    Raises:
        OSError: If the file cannot be written.
    """
    qr: QRCode[qrcode.image.base.BaseImage] = QRCode(
        error_correction=QR_ERROR_CORRECTION,
        box_size=QR_BOX_SIZE,
        border=QR_BORDER,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(str(output))


def render_terminal(uri: str) -> str:
    """Render *uri* as an ASCII-art QR code string for terminal display.

    Uses Unicode block characters for compact rendering.

    Args:
        uri: ``otpauth://`` provisioning URI.

    Returns:
        Multi-line string with the QR code.
    """
    qr: QRCode[qrcode.image.base.BaseImage] = QRCode(
        error_correction=QR_ERROR_CORRECTION,
        border=QR_BORDER,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    lines: list[str] = []
    for row in matrix:
        lines.append("".join("██" if cell else "  " for cell in row))
    return "\n".join(lines)
