from __future__ import annotations

import logging
import re

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
        loader.add_option(
            name="cache_max_body_size",
            typespec=int,
            default=0,
            help=(
                "Maximum response body size in bytes to cache. "
                "0 means no limit. Responses larger than this are skipped."
            ),
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
        3. If the request doesn't have a cache key, forward to origin without
          caching (no UUID fallback — keyless requests are not cacheable).
        """
        if getattr(self, "_closed", False):
            logger.warning("Cache.request() called after done(); skipping.")
            return
        # Get cache key from request headers
        cache_key = self.get_cache_key_from_flow(flow)
        # Cache key header is a proxy-internal hint; never forward it to the
        # origin regardless of cache hit / miss / no-key. Pop once here so
        # all branches stay symmetric and a future branch cannot leak it.
        flow.request.headers.pop(self.cache_key, None)

        cache_from_origin = True

        # Get response from cache
        if cache_key is not None and self._set_cached_response(flow, cache_key):
            cache_from_origin = False

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
        if flow.response is not None:
            flow.response.headers.pop(self.cache_key, None)

        # Check if the response has a cache key
        cache_key = self.get_cache_key_from_flow(flow)
        if flow.metadata.get(self.cache_from_origin, False) and cache_key is not None:
            self._store_response(cache_key, flow)

    def _store_response(self, cache_key: str, flow: http.HTTPFlow) -> None:
        """Best-effort cache write; storage failures leave the flow uncached."""
        # Do not cache error responses; a cached 4xx/5xx would be served
        # indefinitely even after the origin recovers.
        if flow.response is None or flow.response.status_code >= 400:
            return
        if self._response_body_exceeds_limit(flow, cache_key):
            return
        try:
            self.storage.upsert(cache_key, flow)
            logger.info(f"Cache stored: {_sanitize_for_log(cache_key)}")
        except Exception:
            logger.exception(
                "Cache storage write failed for key %s; response not cached",
                _sanitize_for_log(cache_key),
            )

    def _response_body_exceeds_limit(
        self, flow: http.HTTPFlow, cache_key: str
    ) -> bool:
        max_size = int(ctx.options.cache_max_body_size)
        if (
            max_size > 0
            and flow.response is not None
            and len(flow.response.content) > max_size
        ):
            logger.warning(
                f"Cache skipped: body "
                f"{len(flow.response.content)} bytes "
                f"> cache_max_body_size {max_size} "
                f"({_sanitize_for_log(cache_key)})"
            )
            return True
        return False

    def _set_cached_response(self, flow: HTTPFlow, cache_key: str) -> bool:
        """Best-effort cache read; storage failures bypass the cache."""
        try:
            cache = self.storage.get(cache_key)
        except Exception:
            logger.exception(
                "Cache storage read failed for key %s; bypassing cache",
                _sanitize_for_log(cache_key),
            )
            return False
        if cache is None:
            return False
        if cache.response is None:
            logger.warning(
                "Ignoring cached flow without response: %s",
                _sanitize_for_log(cache_key),
            )
            self.storage.purge(cache_key)
            return False

        logger.info(f"Cache hit: {_sanitize_for_log(cache_key)}")
        flow.response = cache.response
        flow.metadata[self.cache_key] = cache_key
        return True

    def get_cache_key_from_flow(self, flow: HTTPFlow) -> str | None:
        for candidate in self.cache_key_candidates(flow):
            if candidate is not None:
                return candidate
        return None

    def cache_key_candidates(
        self, flow: HTTPFlow
    ) -> list[str | None]:
        candidates: list[str | None] = [
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


_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize_for_log(value: str) -> str:
    """Escape control characters so external input cannot inject log lines."""
    return _CONTROL_CHARS_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", value)
