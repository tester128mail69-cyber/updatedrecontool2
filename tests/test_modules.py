"""Tests for GODRECON recon module interface and individual recon modules.

Covers:
* Base module interface contract (abstract class, run wrapper, error handling)
* DNSIntelModule  — mocked DNS resolver and HTTP client
* HTTPProbeModule — mocked HTTP client / prober
* PortScannerModule — mocked TCP scanner
"""

from __future__ import annotations

from typing import Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult


# ---------------------------------------------------------------------------
# Helpers: concrete minimal module for base-interface tests
# ---------------------------------------------------------------------------


class _EchoModule(BaseModule):
    """Minimal concrete module that echoes a single finding."""

    name = "echo"
    description = "Echo module for testing"
    category = "test"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        return ModuleResult(
            module_name=self.name,
            target=target,
            findings=[Finding(title=f"Echo: {target}")],
        )


class _EmptyModule(BaseModule):
    """Module that returns no findings."""

    name = "empty"
    description = "Empty module"
    category = "test"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        return ModuleResult(module_name=self.name, target=target)


class _ErrorModule(BaseModule):
    """Module that always raises an exception."""

    name = "error_module"
    description = "Always raises"
    category = "test"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        raise ValueError("intentional test error")


# ---------------------------------------------------------------------------
# Base module interface tests
# ---------------------------------------------------------------------------


def test_base_module_cannot_be_instantiated():
    """BaseModule is abstract and must not be instantiatable directly."""
    with pytest.raises(TypeError):
        BaseModule()  # type: ignore[abstract]


def test_concrete_module_instantiation():
    mod = _EchoModule()
    assert mod.name == "echo"
    assert mod.category == "test"


def test_module_repr():
    mod = _EchoModule()
    assert "echo" in repr(mod)


@pytest.mark.asyncio
async def test_module_run_returns_module_result():
    mod = _EchoModule()
    result = await mod.run("example.com", Config())
    assert isinstance(result, ModuleResult)


@pytest.mark.asyncio
async def test_module_run_sets_target():
    mod = _EchoModule()
    result = await mod.run("target.example.com", Config())
    assert result.target == "target.example.com"


@pytest.mark.asyncio
async def test_module_run_sets_module_name():
    mod = _EchoModule()
    result = await mod.run("example.com", Config())
    assert result.module_name == "echo"


@pytest.mark.asyncio
async def test_module_run_populates_findings():
    mod = _EchoModule()
    result = await mod.run("example.com", Config())
    assert len(result.findings) == 1
    assert "example.com" in result.findings[0].title


@pytest.mark.asyncio
async def test_module_run_records_duration():
    mod = _EchoModule()
    result = await mod.run("example.com", Config())
    assert result.duration >= 0.0


@pytest.mark.asyncio
async def test_module_run_no_error_on_success():
    mod = _EchoModule()
    result = await mod.run("example.com", Config())
    assert result.error is None


@pytest.mark.asyncio
async def test_module_run_captures_exception():
    """BaseModule.run must catch exceptions and surface them via result.error."""
    mod = _ErrorModule()
    result = await mod.run("example.com", Config())
    assert result.error == "intentional test error"
    assert result.findings == []


@pytest.mark.asyncio
async def test_module_run_empty_findings():
    mod = _EmptyModule()
    result = await mod.run("example.com", Config())
    assert result.findings == []
    assert result.error is None


def test_finding_defaults():
    f = Finding(title="test")
    assert f.severity == "info"
    assert f.confidence == 1.0
    assert f.data == {}
    assert f.tags == []


def test_finding_custom_severity():
    f = Finding(title="SQL Injection", severity="critical")
    assert f.severity == "critical"


def test_module_result_raw_default():
    mr = ModuleResult(module_name="m", target="t")
    assert mr.raw == {}


# ---------------------------------------------------------------------------
# Module 1: PortScannerModule — mock _scan_all
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_port_scanner_no_open_ports():
    """PortScannerModule returns an empty findings list when no ports are open."""
    from godrecon.modules.ports.scanner import PortScannerModule

    mod = PortScannerModule()
    with patch.object(mod, "_scan_all", new_callable=AsyncMock, return_value=[]):
        result = await mod.run("192.0.2.1", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "ports"
    assert result.findings == []
    assert result.error is None


@pytest.mark.asyncio
async def test_port_scanner_open_port_produces_finding():
    """PortScannerModule adds one Finding per open port."""
    from godrecon.modules.ports.scanner import PortScannerModule

    mod = PortScannerModule()
    open_ports = [{"port": 80, "state": "open", "latency": 0.001}]
    with patch.object(mod, "_scan_all", new_callable=AsyncMock, return_value=open_ports):
        result = await mod.run("192.0.2.1", Config())

    assert len(result.findings) == 1
    assert "80" in result.findings[0].title or result.findings[0].data.get("port") == 80


@pytest.mark.asyncio
async def test_port_scanner_multiple_open_ports():
    """PortScannerModule adds one Finding per open port for multiple ports."""
    from godrecon.modules.ports.scanner import PortScannerModule

    mod = PortScannerModule()
    open_ports = [
        {"port": 22, "state": "open", "latency": 0.002},
        {"port": 80, "state": "open", "latency": 0.001},
        {"port": 443, "state": "open", "latency": 0.001},
    ]
    with patch.object(mod, "_scan_all", new_callable=AsyncMock, return_value=open_ports):
        result = await mod.run("192.0.2.1", Config())

    assert len(result.findings) == 3


@pytest.mark.asyncio
async def test_port_scanner_raw_contains_open_ports():
    """PortScannerModule.raw should list open port records."""
    from godrecon.modules.ports.scanner import PortScannerModule

    mod = PortScannerModule()
    open_ports = [{"port": 8080, "state": "open", "latency": 0.005}]
    with patch.object(mod, "_scan_all", new_callable=AsyncMock, return_value=open_ports):
        result = await mod.run("192.0.2.2", Config())

    assert "open_ports" in result.raw
    assert len(result.raw["open_ports"]) == 1
    assert result.raw["open_ports"][0]["port"] == 8080


# ---------------------------------------------------------------------------
# Module 2: DNSIntelModule — mock AsyncDNSResolver and AsyncHTTPClient
# ---------------------------------------------------------------------------


def _make_mock_resolver() -> MagicMock:
    """Build a mock AsyncDNSResolver that supports async context manager."""
    resolver = MagicMock()
    resolver.resolve = AsyncMock(return_value=[])
    resolver.bulk_resolve = AsyncMock(return_value={})
    resolver.detect_wildcard = AsyncMock(return_value=False)
    resolver.__aenter__ = AsyncMock(return_value=resolver)
    resolver.__aexit__ = AsyncMock(return_value=None)
    return resolver


def _make_mock_http_client() -> MagicMock:
    """Build a mock AsyncHTTPClient that supports async context manager."""
    client = MagicMock()
    client.get = AsyncMock(return_value=MagicMock(status=200, text=AsyncMock(return_value="")))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


@pytest.mark.asyncio
async def test_dns_intel_module_returns_module_result(mock_domains: List[str]):
    """DNSIntelModule.run returns a ModuleResult for each domain."""
    from godrecon.modules.dns.dns_intel import DNSIntelModule

    mod = DNSIntelModule()

    mock_resolver = _make_mock_resolver()
    mock_http = _make_mock_http_client()

    with (
        patch("godrecon.modules.dns.dns_intel.AsyncDNSResolver", return_value=mock_resolver),
        patch("godrecon.modules.dns.dns_intel.AsyncHTTPClient", return_value=mock_http),
    ):
        result = await mod.run(mock_domains[0], Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "dns"
    assert result.target == mock_domains[0]


@pytest.mark.asyncio
async def test_dns_intel_module_no_error_with_empty_dns(mock_domains: List[str]):
    """DNSIntelModule completes without error when DNS returns empty records."""
    from godrecon.modules.dns.dns_intel import DNSIntelModule

    mod = DNSIntelModule()

    mock_resolver = _make_mock_resolver()
    mock_http = _make_mock_http_client()

    with (
        patch("godrecon.modules.dns.dns_intel.AsyncDNSResolver", return_value=mock_resolver),
        patch("godrecon.modules.dns.dns_intel.AsyncHTTPClient", return_value=mock_http),
    ):
        result = await mod.run(mock_domains[0], Config())

    assert result.error is None


@pytest.mark.asyncio
async def test_dns_intel_module_target_propagated(mock_domains: List[str]):
    """DNSIntelModule.run records the correct target in the result."""
    from godrecon.modules.dns.dns_intel import DNSIntelModule

    mod = DNSIntelModule()
    target = mock_domains[2]  # "api.example.com"

    mock_resolver = _make_mock_resolver()
    mock_http = _make_mock_http_client()

    with (
        patch("godrecon.modules.dns.dns_intel.AsyncDNSResolver", return_value=mock_resolver),
        patch("godrecon.modules.dns.dns_intel.AsyncHTTPClient", return_value=mock_http),
    ):
        result = await mod.run(target, Config())

    assert result.target == target


# ---------------------------------------------------------------------------
# Module 3: HTTPProbeModule — mock HTTPProber.probe_target
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_probe_module_no_live_hosts():
    """HTTPProbeModule returns a single 'no services found' finding when nothing responds."""
    from godrecon.modules.http.probe import HTTPProbeModule
    from godrecon.modules.http.http_probe import HTTPProber

    mod = HTTPProbeModule()

    mock_http = _make_mock_http_client()

    with (
        patch("godrecon.modules.http.probe.AsyncHTTPClient", return_value=mock_http),
        patch.object(HTTPProber, "probe_target", new_callable=AsyncMock, return_value=[]),
    ):
        result = await mod.run("example.com", Config())

    assert isinstance(result, ModuleResult)
    assert result.module_name == "http"
    assert result.error is None
    # When no hosts respond, the module adds a single informational finding
    assert len(result.findings) >= 1
    assert any("No HTTP" in f.title or "no" in f.title.lower() for f in result.findings)


@pytest.mark.asyncio
async def test_http_probe_module_live_host_produces_finding(fake_http_response):
    """HTTPProbeModule adds a finding for each responding host."""
    from godrecon.modules.http.probe import HTTPProbeModule
    from godrecon.modules.http.http_probe import HTTPProber, ProbeResult

    mod = HTTPProbeModule()

    probe = ProbeResult(
        original_url="http://example.com",
        url="http://example.com",
        status_code=200,
        headers={"content-type": "text/html"},
        title="Example Domain",
        content_length=1234,
        content_type="text/html",
        redirect_chain=[],
        response_time=0.1,
        server="nginx",
        http2=False,
        body_hash="abc123",
        body="<html>Example</html>",
        error=None,
    )

    mock_http = _make_mock_http_client()

    with (
        patch("godrecon.modules.http.probe.AsyncHTTPClient", return_value=mock_http),
        patch.object(HTTPProber, "probe_target", new_callable=AsyncMock, return_value=[probe]),
    ):
        result = await mod.run("example.com", Config())

    assert result.module_name == "http"
    assert len(result.findings) >= 1


@pytest.mark.asyncio
async def test_http_probe_module_result_contains_live_hosts(fake_http_response):
    """HTTPProbeModule.raw should list live HTTP hosts."""
    from godrecon.modules.http.probe import HTTPProbeModule
    from godrecon.modules.http.http_probe import HTTPProber, ProbeResult

    mod = HTTPProbeModule()

    probe = ProbeResult(
        original_url="https://example.com",
        url="https://example.com",
        status_code=200,
        headers={},
        title="",
        content_length=0,
        content_type="text/html",
        redirect_chain=[],
        response_time=0.05,
        server="",
        http2=False,
        body_hash="",
        body="",
        error=None,
    )

    mock_http = _make_mock_http_client()

    with (
        patch("godrecon.modules.http.probe.AsyncHTTPClient", return_value=mock_http),
        patch.object(HTTPProber, "probe_target", new_callable=AsyncMock, return_value=[probe]),
    ):
        result = await mod.run("example.com", Config())

    assert "live_hosts" in result.raw
    assert len(result.raw["live_hosts"]) == 1
