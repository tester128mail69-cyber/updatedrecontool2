"""Tests for godrecon.core.rate_limiter."""

from __future__ import annotations

import asyncio
import time

import pytest

from godrecon.core.rate_limiter import RateLimiter


# ---------------------------------------------------------------------------
# Constructor tests
# ---------------------------------------------------------------------------

def test_rate_limiter_default_burst_equals_rate():
    rl = RateLimiter(max_requests_per_second=5)
    assert rl._burst == 5.0


def test_rate_limiter_custom_burst():
    rl = RateLimiter(max_requests_per_second=5, burst_size=20)
    assert rl._burst == 20.0


def test_rate_limiter_invalid_rate_raises():
    with pytest.raises(ValueError):
        RateLimiter(max_requests_per_second=0)
    with pytest.raises(ValueError):
        RateLimiter(max_requests_per_second=-1)


# ---------------------------------------------------------------------------
# try_acquire tests (non-blocking)
# ---------------------------------------------------------------------------

def test_try_acquire_succeeds_with_full_bucket():
    rl = RateLimiter(max_requests_per_second=10)
    assert rl.try_acquire() is True


def test_try_acquire_fails_when_bucket_empty():
    rl = RateLimiter(max_requests_per_second=10, burst_size=1)
    assert rl.try_acquire() is True   # drains the single token
    assert rl.try_acquire() is False  # bucket is now empty


def test_try_acquire_refills_over_time():
    rl = RateLimiter(max_requests_per_second=100, burst_size=1)
    rl.try_acquire()  # drain
    time.sleep(0.02)  # wait long enough for >1 token at 100/s
    assert rl.try_acquire() is True


def test_try_acquire_is_non_blocking():
    rl = RateLimiter(max_requests_per_second=1, burst_size=1)
    rl.try_acquire()  # drain
    start = time.monotonic()
    result = rl.try_acquire()
    elapsed = time.monotonic() - start
    assert result is False
    assert elapsed < 0.01  # must return immediately


# ---------------------------------------------------------------------------
# acquire tests (async)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_acquire_succeeds_with_full_bucket():
    rl = RateLimiter(max_requests_per_second=100)
    await rl.acquire()  # should complete without blocking


@pytest.mark.asyncio
async def test_acquire_waits_when_bucket_empty():
    """acquire() should wait until a token is available."""
    rl = RateLimiter(max_requests_per_second=50, burst_size=1)
    await rl.acquire()  # drain

    start = time.monotonic()
    await rl.acquire()  # should wait ~1/50 = 0.02s
    elapsed = time.monotonic() - start

    assert elapsed >= 0.01  # waited at least a bit


@pytest.mark.asyncio
async def test_acquire_concurrent_respects_rate():
    """Multiple concurrent acquires should each take a token."""
    rl = RateLimiter(max_requests_per_second=100, burst_size=5)
    # Drain 5 tokens quickly (burst available)
    tasks = [asyncio.create_task(rl.acquire()) for _ in range(5)]
    await asyncio.gather(*tasks)
    # All 5 should have succeeded; bucket now ~empty
    assert rl._tokens < 1.0


# ---------------------------------------------------------------------------
# Engine integration: rate_limit config is wired up
# ---------------------------------------------------------------------------

def test_engine_creates_rate_limiter_when_rate_limit_set():
    from godrecon.core.config import Config
    from godrecon.core.engine import ScanEngine

    cfg = Config()
    cfg.general.rate_limit = 5
    engine = ScanEngine(target="example.com", config=cfg)
    assert engine._rate_limiter is not None
    assert engine._rate_limiter._rate == 5.0


def test_engine_no_rate_limiter_when_rate_limit_zero():
    from godrecon.core.config import Config
    from godrecon.core.engine import ScanEngine

    cfg = Config()
    cfg.general.rate_limit = 0
    engine = ScanEngine(target="example.com", config=cfg)
    assert engine._rate_limiter is None


def test_engine_default_rate_limit_is_ten():
    from godrecon.core.config import GeneralConfig

    cfg = GeneralConfig()
    assert cfg.rate_limit == 10
