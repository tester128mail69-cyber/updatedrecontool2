"""Shared pytest fixtures for the GODRECON test suite."""

from __future__ import annotations

from typing import Callable, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from godrecon.core.config import Config


@pytest.fixture
def sample_config() -> Config:
    """Return a default Config instance with no external dependencies."""
    return Config()


@pytest.fixture
def mock_http_client() -> MagicMock:
    """Return a MagicMock simulating an async HTTP client."""
    client = MagicMock()
    client.get = AsyncMock(return_value=MagicMock(status=200, text=AsyncMock(return_value="")))
    client.post = AsyncMock(return_value=MagicMock(status=200, text=AsyncMock(return_value="")))
    return client


@pytest.fixture
def mock_dns_resolver() -> MagicMock:
    """Return a MagicMock simulating an async DNS resolver."""
    resolver = MagicMock()
    resolver.resolve = AsyncMock(return_value=[])
    return resolver


@pytest.fixture
def tmp_config() -> dict:
    """Return a minimal config dict for tests that need a lightweight configuration."""
    return {
        "general": {
            "threads": 10,
            "timeout": 5,
            "retries": 1,
        },
        "dns": {
            "resolvers": ["8.8.8.8"],
        },
    }


@pytest.fixture
def mock_domains() -> List[str]:
    """Return a list of sample domain names for use in tests."""
    return [
        "example.com",
        "test.example.com",
        "api.example.com",
        "staging.example.org",
        "dev.internal.example.net",
    ]


@pytest.fixture
def fake_http_response() -> Callable[..., MagicMock]:
    """Return a factory that creates fake aiohttp-style HTTP response mocks.

    Usage::

        def test_something(fake_http_response):
            resp = fake_http_response(status=200, body="<html>Hello</html>")
            assert resp.status == 200
    """

    def _make_response(
        status: int = 200,
        body: str = "",
        headers: Dict[str, str] | None = None,
        url: str = "http://example.com",
    ) -> MagicMock:
        resp = MagicMock()
        resp.status = status
        resp.url = url
        resp.headers = headers or {"Content-Type": "text/html"}
        resp.text = AsyncMock(return_value=body)
        resp.read = AsyncMock(return_value=body.encode())
        resp.json = AsyncMock(return_value={})
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)
        return resp

    return _make_response
