from __future__ import annotations

import logging
import os
from uuid import uuid4

from mitmproxy import ctx, http
from mitmproxy.addonmanager import Loader
from mitmproxy.http import HTTPFlow

from mitmcache.cache_sqlite3_storage import SQLiteCacheStorage
from mitmcache.cache_storage import CacheStorage

# Environment variable for specifying the cache file path
CACHE_FILE_ENV = "MITMPROXY_CACHE_FILE"  # default: cache.db
DEFAULT_CACHE_FILE = "cache.db"
CACHE_KEY_HEADER = "Mitm-Cache-Key"
FROM_ORIGIN = "Mitm-Cache-From-Origin"
logger = logging.getLogger(__name__)


class Cache:
    storage: CacheStorage

    def __init__(self) -> None:
        # Initialize cache storage
        cache_file = os.environ.get(CACHE_FILE_ENV, DEFAULT_CACHE_FILE)
        # TODO: Add support for other cache storages
        self.storage = SQLiteCacheStorage(cache_file)

    def load(self, loader: Loader) -> None:
        # Add option for specifying cache header
        loader.add_option(
            name="cache_header",
            typespec=str,
            default=CACHE_KEY_HEADER,
            help="Header used to determine the cache key.",
        )

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
        cache_key = get_cache_key_from_flow(flow)
        search_cache = True if cache_key is not None else False

        # Get response from cache
        if search_cache and cache_key:
            cache = self.storage.get(cache_key)
            if cache is not None:
                assert cache.response is not None
                logger.info(f"Cache hit: {cache_key}")
                flow.response = cache.response
                flow.response.headers[ctx.options.cache_header] = cache_key
                flow.metadata[ctx.options.cache_header] = cache_key
                flow.metadata[FROM_ORIGIN] = False
        else:
            cache_key = generate_cache_key_by_uuid()
            # Remove header before sending to origin server
            flow.request.headers.pop(ctx.options.cache_header, None)

        # Set cache key to flow
        flow.metadata[ctx.options.cache_header] = cache_key
        flow.metadata[FROM_ORIGIN] = True

    def response(self, flow: http.HTTPFlow) -> None:
        """response

        1. If the response has a cache key, do nothing.
        2. If the response doesn't have a cache key,
           that means the request has sent to the origin and it will be cached.
        """

        # Check if the response has a cache key
        cache_key = get_cache_key_from_flow(flow)

        if flow.metadata.get(FROM_ORIGIN, False) and cache_key:
            cache = self.storage.get(cache_key)
            if cache is not None:
                self.storage.update(cache_key, flow)
                logger.info(f"Cache updated: {cache_key}")
            else:
                self.storage.store(cache_key, flow)
                logger.info(f"Cache stored: {cache_key}")

    def done(self) -> None:
        self.storage.close()


def get_cache_key_from_flow(flow: HTTPFlow) -> str | None:
    # 1. Try from flow metadata
    cache_key = flow.metadata.get(ctx.options.cache_header)
    if cache_key is not None:
        return str(cache_key)
    # 2. Try from request headers
    cache_key = flow.request.headers.get(ctx.options.cache_header)
    if cache_key is not None:
        return str(cache_key)
    # 3. Try from response headers
    if not flow.response:
        return None
    cache_key = flow.response.headers.get(ctx.options.cache_header)
    if cache_key:
        return str(cache_key)
    return None


def generate_cache_key_by_uuid() -> str:
    # Generate cache key by uuid
    return str(uuid4())
