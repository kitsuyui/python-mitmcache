from __future__ import annotations

import logging
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
            help="Header used to determine\
 whether the request is from the origin",
        )
        self.storage_factory = StorageFactory()
        self.storage_factory.load(loader)

    def configure(self, updated: set[str]) -> None:
        self.storage = self.storage_factory.create()

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
        # Get cache key or create it from request headers
        cache_key = self.get_cache_key_from_flow(flow)
        search_cache = True if cache_key is not None else False

        # Get response from cache
        if search_cache and cache_key:
            cache = self.storage.get(cache_key)
            if cache is not None:
                assert cache.response is not None
                logger.info(f"Cache hit: {cache_key}")
                flow.response = cache.response
                flow.response.headers[self.cache_key] = cache_key
                flow.metadata[self.cache_key] = cache_key
                flow.metadata[self.cache_from_origin] = False
        else:
            cache_key = generate_cache_key_by_uuid()
            # Remove header before sending to origin server
            flow.request.headers.pop(self.cache_key, None)

        # Set cache key to flow
        flow.metadata[self.cache_key] = cache_key
        flow.metadata[self.cache_from_origin] = True

    def response(self, flow: http.HTTPFlow) -> None:
        """response

        1. If the response has a cache key, do nothing.
        2. If the response doesn't have a cache key,
           that means the request has sent to the origin and it will be cached.
        """

        # Check if the response has a cache key
        cache_key = self.get_cache_key_from_flow(flow)
        if flow.metadata.get(self.cache_from_origin, False) and cache_key:
            cache = self.storage.get(cache_key)
            if cache is not None:
                self.storage.update(cache_key, flow)
                logger.info(f"Cache updated: {cache_key}")
            else:
                self.storage.store(cache_key, flow)
                logger.info(f"Cache stored: {cache_key}")

    def get_cache_key_from_flow(self, flow: HTTPFlow) -> str | None:
        # 1. Try from flow metadata
        cache_key = flow.metadata.get(self.cache_key)
        if cache_key is not None:
            return str(cache_key)
        # 2. Try from request headers
        cache_key = flow.request.headers.get(self.cache_key)
        if cache_key is not None:
            return str(cache_key)
        # 3. Try from response headers
        if not flow.response:
            return None
        cache_key = flow.response.headers.get(self.cache_key)
        if cache_key:
            return str(cache_key)
        return None

    def done(self) -> None:
        self.storage.close()


def generate_cache_key_by_uuid() -> str:
    # Generate cache key by uuid
    return str(uuid4())
