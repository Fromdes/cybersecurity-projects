"""FastAPI application for the Secure REST API Template."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .core import APIKeyStore, RateLimiter, get_security_headers, verify_request_signature

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global state (replace with persistent store in production)
# ---------------------------------------------------------------------------

_key_store = APIKeyStore()
_rate_limiter = RateLimiter()
_api_secret = os.environ.get("API_HMAC_SECRET", "dev-secret-change-me").encode()

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Secure REST API",
    version="0.1.0",
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/openapi.json",
)


# ---------------------------------------------------------------------------
# Middleware: security headers
# ---------------------------------------------------------------------------

@app.middleware("http")
async def add_security_headers(request: Request, call_next: Any) -> Response:
    response: Response = await call_next(request)
    for name, value in get_security_headers().items():
        response.headers[name] = value
    return response


# ---------------------------------------------------------------------------
# Middleware: rate limiting
# ---------------------------------------------------------------------------

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next: Any) -> Response:
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_limiter.is_allowed(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded"},
            headers={"Retry-After": str(_rate_limiter.window)},
        )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _require_api_key(authorization: str | None, scope: str | None = None) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    key = authorization.removeprefix("Bearer ").strip()
    try:
        return _key_store.validate_key(key, required_scope=scope)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

class CreateKeyRequest(BaseModel):
    owner: str
    scopes: list[str] = ["read"]


class CreateKeyResponse(BaseModel):
    api_key: str
    owner: str
    scopes: list[str]


@app.post("/keys", response_model=CreateKeyResponse, status_code=201)
def create_key(body: CreateKeyRequest) -> CreateKeyResponse:
    """Create a new API key (admin use; protect this endpoint in production)."""
    key = _key_store.create_key(owner=body.owner, scopes=body.scopes)
    return CreateKeyResponse(api_key=key, owner=body.owner, scopes=body.scopes)


@app.get("/health")
def health() -> dict[str, str]:
    """Public health check endpoint."""
    return {"status": "ok"}


@app.get("/protected")
def protected_route(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Protected endpoint requiring a valid API key with 'read' scope."""
    meta = _require_api_key(authorization, scope="read")
    return {"message": "Access granted", "owner": meta["owner"]}


@app.post("/signed")
async def signed_route(
    request: Request,
    x_timestamp: str | None = Header(default=None),
    x_signature: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    """HMAC-signed request endpoint."""
    _require_api_key(authorization)
    if not x_timestamp or not x_signature:
        raise HTTPException(status_code=400, detail="Missing X-Timestamp or X-Signature headers")
    body = await request.body()
    try:
        verify_request_signature(
            method=request.method,
            path=request.url.path,
            body=body,
            timestamp=x_timestamp,
            submitted_sig=x_signature,
            secret=_api_secret,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return {"message": "Signed request accepted"}
