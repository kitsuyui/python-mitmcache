from __future__ import annotations

from typing import Protocol

from mitmproxy import http


class CacheStorage(Protocol):
    def get(self, cache_key: str) -> http.HTTPFlow | None:
        """Get response from cache with specified cache key."""

    def store(self, cache_key: str, flow: http.HTTPFlow) -> None:
        """Store flow in cache with specified cache key."""

    def purge(self, cache_key: str) -> None:
        """Remove flow from cache with specified cache key."""

    def update(self, cache_key: str, flow: http.HTTPFlow) -> None:
        """Update flow in cache with specified cache key."""

    def close(self) -> None:
        """Close cache storage."""
