"""Token-bucket rate limiter for GODRECON.

Provides :class:`RateLimiter` — a thread-safe, asyncio-compatible token-bucket
implementation used to control the rate of outbound requests across all
HTTP-based scan modules.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional


class RateLimiter:
    """Token-bucket rate limiter.

    Tokens are added to the bucket at *max_requests_per_second* per second up
    to a maximum of *burst_size*.  Each call to :meth:`acquire` (or a
    successful :meth:`try_acquire`) consumes one token.

    Example::

        limiter = RateLimiter(max_requests_per_second=10, burst_size=20)
        await limiter.acquire()   # waits if the bucket is empty
        if limiter.try_acquire(): # non-blocking check
            ...

    Args:
        max_requests_per_second: Sustained token refill rate (tokens/second).
            Must be a positive number.
        burst_size: Maximum tokens the bucket can hold.  Defaults to
            *max_requests_per_second* when ``None`` or ``0``.
    """

    def __init__(
        self,
        max_requests_per_second: float,
        burst_size: Optional[int] = None,
    ) -> None:
        if max_requests_per_second <= 0:
            raise ValueError("max_requests_per_second must be positive")
        self._rate: float = max_requests_per_second
        self._burst: float = float(burst_size) if burst_size else max_requests_per_second
        # Start with a full bucket
        self._tokens: float = self._burst
        self._last_refill: float = time.monotonic()
        self._lock: asyncio.Lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _refill(self) -> None:
        """Add tokens accrued since the last call (must be called under lock)."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._last_refill = now

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def acquire(self) -> None:
        """Acquire one token, waiting asynchronously if the bucket is empty.

        Suspends the current coroutine until a token becomes available without
        blocking the event loop.
        """
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Calculate how long until the next token is available
                wait = (1.0 - self._tokens) / self._rate
                # Release the lock while sleeping so other coroutines can run
                self._lock.release()
                try:
                    await asyncio.sleep(wait)
                finally:
                    await self._lock.acquire()

    def try_acquire(self) -> bool:
        """Attempt to acquire one token without blocking.

        This method is safe to call from asyncio code: because it contains no
        ``await`` points it runs atomically within asyncio's single-threaded
        cooperative event loop — no other coroutine can interleave during its
        execution.  It is **not** safe to call from multiple OS threads
        simultaneously.

        Returns:
            ``True`` if a token was available and consumed; ``False`` otherwise.
        """
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._last_refill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False
