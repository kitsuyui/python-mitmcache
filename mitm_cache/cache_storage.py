from __future__ import annotations

from typing import Protocol

from mitmproxy import http


class CacheStorage(Protocol):
    def get_response(self, cache_key: str) -> http.Response | None:
        pass

    def store_response(self, cache_key: str, response: http.HTTPFlow) -> None:
        pass

    def close(self) -> None:
        pass
