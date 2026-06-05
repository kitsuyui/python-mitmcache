from __future__ import annotations

import logging
import re
from uuid import uuid4

from mitmproxy import ctx, http
from mitmproxy.addonmanager import Loader
from mitmproxy.http import HTTPFlow

from mitmcache.storage.cache_storage import CacheStorage
from mitmcache.storage.factory import StorageFactory

logger = logging.getLogger(__name__)


class Cache:
    storage_factory: StorageFactory
    storage: CacheStorage

    def load(self, loader: Loader) -> None:
        loader.add_option(
            name="cache_key",
            typespec=str,
            default="Mitm-Cache-Key",
            help="Header used to determine the cache key.",
        )
        loader.add_option(
            name="cache_from_origin",
            typespec=str,
            default="Mitm-Cache-From-Origin",
            help="flow.metadata key used internally to track whether the"
            " response should be fetched from the origin (not an HTTP"
            " header name).",
        )
        self.storage_factory = StorageFactory()
        self.storage_factory.load(loader)

    def configure(self, updated: set[str]) -> None:
        existing = getattr(self, "storage", None)
        if (
            existing is not None
            and "cache_file" not in updated
            and "cache_max_entries" not in updated
        ):
            return
        self.storage = self.storage_factory.create()
        if existing is not None:
            existing.close()
        self._closed = False

    @property
    def cache_key(self) -> str:
        return str(ctx.options.cache_key)

    @property
    def cache_from_origin(self) -> str:
        return str(ctx.options.cache_from_origin)

    def request(self, flow: HTTPFlow) -> None:
        """request

        1. If the request has a cache key and already exists in the cache,
          set the response to the cached response.
        2. If the request has a cache key but doesn't exist in the cache,
          request to the origin server without cache key header.
        3. If the request doesn't have a cache key,
          generate a cache key and set it to the response headers.
        """
        if getattr(self, "_closed", False):
            logger.warning("Cache.request() called after done(); skipping.")
            return
        # Get cache key or create it from request headers
        cache_key = self.get_cache_key_from_flow(flow)
        # Cache key header is a proxy-internal hint; never forward it to the
        # origin regardless of cache hit / miss / no-key. Pop once here so
        # all branches stay symmetric and a future branch cannot leak it.
        flow.request.headers.pop(self.cache_key, None)
        search_cache = True if cache_key is not None else False

        cache_from_origin = True

        # Get response from cache
        if search_cache and cache_key:
            cache = self.storage.get(cache_key)
            if cache is not None:
                assert cache.response is not None
                logger.info(f"Cache hit: {_sanitize_for_log(cache_key)}")
                flow.response = cache.response
                flow.metadata[self.cache_key] = cache_key
                cache_from_origin = False
        else:
            cache_key = generate_cache_key_by_uuid()

        # Set cache key to flow
        flow.metadata[self.cache_key] = cache_key
        flow.metadata[self.cache_from_origin] = cache_from_origin

    def response(self, flow: http.HTTPFlow) -> None:
        """response

        1. If the response has a cache key, do nothing.
        2. If the response doesn't have a cache key,
           that means the request has sent to the origin and it will be cached.
        """
        if getattr(self, "_closed", False):
            logger.warning("Cache.response() called after done(); skipping.")
            return

        # Strip internal header so it never reaches the downstream client.
        flow.response.headers.pop(self.cache_key, None)

        # Check if the response has a cache key
        cache_key = self.get_cache_key_from_flow(flow)
        if flow.metadata.get(self.cache_from_origin, False) and cache_key:
            self.storage.upsert(cache_key, flow)
            logger.info(f"Cache stored: {_sanitize_for_log(cache_key)}")

    def get_cache_key_from_flow(self, flow: HTTPFlow) -> str | None:
        for candidate in self.cache_key_candidates(flow):
            if candidate is not None:
                return str(candidate)
        return None

    def cache_key_candidates(
        self, flow: HTTPFlow
    ) -> list[str | object | None]:
        candidates: list[str | object | None] = [
            flow.metadata.get(self.cache_key),
            flow.request.headers.get(self.cache_key),
        ]
        if flow.response:
            candidates.append(flow.response.headers.get(self.cache_key))
        return candidates

    def done(self) -> None:
        storage = getattr(self, "storage", None)
        if storage is not None:
            storage.close()
        self._closed = True


def generate_cache_key_by_uuid() -> str:
    # Generate cache key by uuid
    return str(uuid4())


_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize_for_log(value: str) -> str:
    """Escape control characters so external input cannot inject log lines."""
    return _CONTROL_CHARS_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", value)
