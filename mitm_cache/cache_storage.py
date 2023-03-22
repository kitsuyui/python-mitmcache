from __future__ import annotations

from typing import Protocol

from mitmproxy import http


class CacheStorage(Protocol):
    def get_response(self, cache_key: str) -> http.Response | None:
        """Get response from cache with specified cache key."""

    def store_response(self, cache_key: str, response: http.HTTPFlow) -> None:
        """Store response in cache with specified cache key."""

    def purge_response(self, cache_key: str) -> None:
        """Remove response from cache with specified cache key."""

    def close(self) -> None:
        """Close cache storage."""
