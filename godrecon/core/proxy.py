"""Proxy and Tor support for GODRECON.

Provides a :class:`ProxyManager` that handles SOCKS5, HTTP, and HTTPS proxy
configuration, automatic proxy rotation from a file, and Tor SOCKS5
auto-detection.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List, Optional


_TOR_PROXY_URL = "socks5://127.0.0.1:9050"


class ProxyManager:
    """Manage proxy configuration for outbound HTTP requests.

    Supports SOCKS5, HTTP, and HTTPS proxies, optional rotation from a
    proxy list file, and a Tor mode that automatically uses the local Tor
    SOCKS5 proxy.

    Example::

        pm = ProxyManager(proxy_url="socks5://127.0.0.1:9050")
        print(pm.get_proxy_url())  # socks5://127.0.0.1:9050

        pm = ProxyManager(tor_mode=True)
        print(pm.get_proxy_url())  # socks5://127.0.0.1:9050
    """

    def __init__(
        self,
        enabled: bool = True,
        proxy_url: Optional[str] = None,
        proxy_list_file: Optional[str] = None,
        rotate: bool = False,
        tor_mode: bool = False,
    ) -> None:
        """Initialise the ProxyManager.

        Args:
            enabled: Whether proxy support is active.
            proxy_url: A single proxy URL to use (e.g. ``socks5://host:port``).
            proxy_list_file: Path to a file with one proxy URL per line.
            rotate: Automatically rotate to the next proxy on each request.
            tor_mode: Use the local Tor SOCKS5 proxy (``socks5://127.0.0.1:9050``).
        """
        self.enabled = enabled
        self.rotate = rotate
        self.tor_mode = tor_mode

        self._proxies: List[str] = []
        self._index: int = 0

        if tor_mode:
            self._proxies = [_TOR_PROXY_URL]
        elif proxy_list_file:
            self._load_proxy_list(proxy_list_file)
        elif proxy_url:
            self._proxies = [proxy_url]

    # ------------------------------------------------------------------
    # Proxy list loading
    # ------------------------------------------------------------------

    def _load_proxy_list(self, filepath: str) -> None:
        """Load proxy URLs from a newline-separated file.

        Args:
            filepath: Path to the proxy list file.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Proxy list file not found: {filepath}")
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                self._proxies.append(line)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get_proxy_url(self) -> Optional[str]:
        """Return the current proxy URL, or ``None`` if proxying is disabled.

        Returns:
            A proxy URL string suitable for use with aiohttp ``proxy=`` or
            the ``requests`` ``proxies`` dict, or ``None`` when disabled.
        """
        if not self.enabled or not self._proxies:
            return None
        return self._proxies[self._index % len(self._proxies)]

    def rotate_proxy(self) -> Optional[str]:
        """Advance to the next proxy in the rotation list and return it.

        Returns:
            The new current proxy URL, or ``None`` if the list is empty.
        """
        if not self._proxies:
            return None
        self._index = (self._index + 1) % len(self._proxies)
        return self._proxies[self._index]

    async def test_proxy(self, url: str = "http://httpbin.org/ip", timeout: int = 10) -> bool:
        """Verify that the current proxy is reachable.

        Performs a simple HTTP GET through the proxy and returns ``True`` on
        a successful (2xx) response.

        Args:
            url: URL to probe through the proxy.
            timeout: Request timeout in seconds.

        Returns:
            ``True`` if the proxy is working, ``False`` otherwise.
        """
        proxy_url = self.get_proxy_url()
        if not proxy_url:
            return False
        try:
            import aiohttp
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    url,
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    return 200 <= resp.status < 300
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def proxy_list(self) -> List[str]:
        """Return a copy of the configured proxy list."""
        return list(self._proxies)

    def __repr__(self) -> str:
        return (
            f"ProxyManager(enabled={self.enabled}, tor_mode={self.tor_mode}, "
            f"proxies={len(self._proxies)}, rotate={self.rotate})"
        )
