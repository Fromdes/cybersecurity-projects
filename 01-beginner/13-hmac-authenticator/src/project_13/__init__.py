"""HMAC Message Authenticator — sign and verify arbitrary messages with HMAC-SHA256/512."""

from project_13.core import (
    HMACResult,
    compute_hmac,
    verify_hmac,
    sign_file,
    verify_file,
)

__all__ = ["HMACResult", "compute_hmac", "verify_hmac", "sign_file", "verify_file"]
