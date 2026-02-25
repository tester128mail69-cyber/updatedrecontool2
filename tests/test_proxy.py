"""Tests for godrecon.core.proxy."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from godrecon.core.proxy import ProxyManager


# ---------------------------------------------------------------------------
# Construction and URL retrieval
# ---------------------------------------------------------------------------

def test_disabled_returns_none():
    pm = ProxyManager(enabled=False, proxy_url="http://proxy:3128")
    assert pm.get_proxy_url() is None


def test_http_proxy_url():
    pm = ProxyManager(proxy_url="http://proxy.example.com:3128")
    assert pm.get_proxy_url() == "http://proxy.example.com:3128"


def test_socks5_proxy_url():
    pm = ProxyManager(proxy_url="socks5://127.0.0.1:1080")
    assert pm.get_proxy_url() == "socks5://127.0.0.1:1080"


def test_https_proxy_url():
    pm = ProxyManager(proxy_url="https://proxy.example.com:8443")
    assert pm.get_proxy_url() == "https://proxy.example.com:8443"


def test_no_proxy_configured_returns_none():
    pm = ProxyManager()
    assert pm.get_proxy_url() is None


# ---------------------------------------------------------------------------
# Tor mode
# ---------------------------------------------------------------------------

def test_tor_mode_uses_localhost_9050():
    pm = ProxyManager(tor_mode=True)
    assert pm.get_proxy_url() == "socks5://127.0.0.1:9050"


def test_tor_mode_sets_correct_proxy_list():
    pm = ProxyManager(tor_mode=True)
    assert pm.proxy_list == ["socks5://127.0.0.1:9050"]


def test_tor_mode_overrides_proxy_url():
    pm = ProxyManager(proxy_url="http://other:3128", tor_mode=True)
    assert pm.get_proxy_url() == "socks5://127.0.0.1:9050"


# ---------------------------------------------------------------------------
# Proxy list file loading
# ---------------------------------------------------------------------------

def test_proxy_list_file_loading(tmp_path):
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text("http://proxy1:3128\n# comment\nsocks5://proxy2:1080\n")
    pm = ProxyManager(proxy_list_file=str(proxy_file))
    assert pm.proxy_list == ["http://proxy1:3128", "socks5://proxy2:1080"]


def test_proxy_list_file_not_found():
    with pytest.raises(FileNotFoundError):
        ProxyManager(proxy_list_file="/nonexistent/proxies.txt")


def test_proxy_list_empty_lines_ignored(tmp_path):
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text("\nhttp://proxy1:3128\n\n")
    pm = ProxyManager(proxy_list_file=str(proxy_file))
    assert pm.proxy_list == ["http://proxy1:3128"]


# ---------------------------------------------------------------------------
# Proxy rotation
# ---------------------------------------------------------------------------

def test_rotate_proxy_advances_index(tmp_path):
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text("http://proxy1:3128\nhttp://proxy2:3128\nhttp://proxy3:3128\n")
    pm = ProxyManager(proxy_list_file=str(proxy_file), rotate=True)
    first = pm.get_proxy_url()
    second = pm.rotate_proxy()
    assert first != second


def test_rotate_proxy_wraps_around(tmp_path):
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text("http://a:1\nhttp://b:2\n")
    pm = ProxyManager(proxy_list_file=str(proxy_file), rotate=True)
    pm.rotate_proxy()  # -> http://b:2
    back = pm.rotate_proxy()  # -> http://a:1
    assert back == "http://a:1"


def test_rotate_empty_list_returns_none():
    pm = ProxyManager()
    assert pm.rotate_proxy() is None


# ---------------------------------------------------------------------------
# test_proxy (async)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_test_proxy_no_proxy():
    pm = ProxyManager()
    result = await pm.test_proxy()
    assert result is False


@pytest.mark.asyncio
async def test_test_proxy_success():
    pm = ProxyManager(proxy_url="http://proxy:3128")

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=None)

    mock_session = MagicMock()
    mock_session.get = MagicMock(return_value=mock_resp)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await pm.test_proxy()
    assert result is True


@pytest.mark.asyncio
async def test_test_proxy_failure():
    pm = ProxyManager(proxy_url="http://proxy:3128")
    with patch("aiohttp.ClientSession", side_effect=Exception("connection refused")):
        result = await pm.test_proxy()
    assert result is False


# ---------------------------------------------------------------------------
# repr
# ---------------------------------------------------------------------------

def test_repr():
    pm = ProxyManager(proxy_url="http://proxy:3128", tor_mode=False)
    assert "ProxyManager" in repr(pm)
    assert "enabled=True" in repr(pm)
