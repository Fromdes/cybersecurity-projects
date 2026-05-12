"""Integration tests for FastAPI app (project 49)."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from project_49.app import app, _key_store, _api_secret
from project_49.core import sign_request

client = TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def read_key() -> str:
    return _key_store.create_key("test-user", ["read"])


class TestHealthEndpoint:
    def test_health_ok(self) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestSecurityHeaders:
    def test_headers_present(self) -> None:
        resp = client.get("/health")
        assert "x-content-type-options" in resp.headers or "X-Content-Type-Options" in resp.headers


class TestProtectedEndpoint:
    def test_no_auth_returns_401(self) -> None:
        resp = client.get("/protected")
        assert resp.status_code == 401

    def test_valid_key_returns_200(self, read_key: str) -> None:
        resp = client.get("/protected", headers={"Authorization": f"Bearer {read_key}"})
        assert resp.status_code == 200
        assert resp.json()["owner"] == "test-user"

    def test_invalid_key_returns_403(self) -> None:
        resp = client.get("/protected", headers={"Authorization": "Bearer bad-key"})
        assert resp.status_code == 403


class TestCreateKey:
    def test_create_key(self) -> None:
        resp = client.post("/keys", json={"owner": "new-user", "scopes": ["read"]})
        assert resp.status_code == 201
        data = resp.json()
        assert data["api_key"].startswith("sk_")
        assert data["owner"] == "new-user"
