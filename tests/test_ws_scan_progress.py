"""Tests for the WebSocket scan progress endpoint ``/ws/scan/{scan_id}``."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")
pytest.importorskip("websockets", reason="websockets not installed")

from godrecon.api.server import app  # noqa: E402
from godrecon.api.models import ScanStatus  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_app():
    """Return the default FastAPI app, skipping if unavailable."""
    if app is None:
        pytest.skip("FastAPI app not available")
    return app


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_ws_scan_progress_not_found():
    """Connecting to a non-existent scan_id should receive an error event."""
    client = TestClient(_get_app())
    with client.websocket_connect("/ws/scan/nonexistent-scan-id") as ws:
        data = json.loads(ws.receive_text())
        assert data["type"] == "error"
        assert data["status"] == "not_found"
        assert data["module_name"] is None
        assert "timestamp" in data


def test_ws_scan_progress_completed_scan():
    """Connecting to a completed scan should receive module_complete events and a scan_complete event."""
    from godrecon.api.scan_manager import ScanRecord
    from godrecon.api.models import ScanStatus

    # Build a completed record manually and inject it into the app's scan_manager
    client = TestClient(_get_app())
    scan_manager = client.app.state.scan_manager  # type: ignore[attr-defined]

    record = scan_manager.create_scan(target="example.com")
    record.modules_completed = ["dns", "http_probe"]
    record.status = ScanStatus.COMPLETED

    with client.websocket_connect(f"/ws/scan/{record.scan_id}") as ws:
        messages = []
        # Expect 2 module_complete + 1 scan_complete = 3 messages
        for _ in range(3):
            messages.append(json.loads(ws.receive_text()))

    types = [m["type"] for m in messages]
    assert "module_complete" in types
    assert "scan_complete" in types

    mod_msgs = [m for m in messages if m["type"] == "module_complete"]
    assert {m["module_name"] for m in mod_msgs} == {"dns", "http_probe"}

    final = next(m for m in messages if m["type"] == "scan_complete")
    assert final["status"] == ScanStatus.COMPLETED.value
    assert final["module_name"] is None
    assert "timestamp" in final


def test_ws_scan_progress_failed_scan():
    """A failed scan should produce a scan_complete event with status 'failed'."""
    client = TestClient(_get_app())
    scan_manager = client.app.state.scan_manager  # type: ignore[attr-defined]

    record = scan_manager.create_scan(target="fail.example.com")
    record.status = ScanStatus.FAILED
    record.error = "engine error"

    with client.websocket_connect(f"/ws/scan/{record.scan_id}") as ws:
        msg = json.loads(ws.receive_text())

    assert msg["type"] == "scan_complete"
    assert msg["status"] == ScanStatus.FAILED.value


def test_ws_scan_progress_event_structure():
    """Every event must include type, module_name, status and timestamp keys."""
    client = TestClient(_get_app())
    scan_manager = client.app.state.scan_manager  # type: ignore[attr-defined]

    record = scan_manager.create_scan(target="struct.example.com")
    record.modules_completed = ["ssl"]
    record.status = ScanStatus.COMPLETED

    with client.websocket_connect(f"/ws/scan/{record.scan_id}") as ws:
        messages = []
        for _ in range(2):  # module_complete + scan_complete
            messages.append(json.loads(ws.receive_text()))

    for msg in messages:
        assert "type" in msg
        assert "module_name" in msg
        assert "status" in msg
        assert "timestamp" in msg
