import os

from mitmproxy import ctx, http
from mitmproxy.addonmanager import Loader
from mitmproxy.http import HTTPFlow

from mitmcache.cache_sqlite3_storage import SQLiteCacheStorage
from mitmcache.cache_storage import CacheStorage

# Environment variable for specifying the cache file path
CACHE_FILE_ENV = "MITMPROXY_CACHE_FILE"  # default: cache.db
DEFAULT_CACHE_FILE = "cache.db"
CACHE_KEY_HEADER = "Mitm-Cache-Key"


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
            "cache_header",
            str,
            CACHE_KEY_HEADER,
            "Header used to determine the cache key.",
        )

    def request(self, flow: HTTPFlow) -> None:
        cache_key = flow.request.headers.get(ctx.options.cache_header)
        if not cache_key:
            return
        cache = self.storage.get(cache_key)
        if cache:
            ctx.log.info(f"Cache hit: {cache_key}")
            flow.response = cache.response
        else:
            ctx.log.info(f"Cache miss: {cache_key}")

    def response(self, flow: http.HTTPFlow) -> None:
        cache_key = flow.request.headers.get(ctx.options.cache_header)
        if not cache_key:
            return
        cache = self.storage.get(cache_key)
        if cache:
            flow.response = cache.response
        else:
            self.storage.store(cache_key, flow)

    def done(self) -> None:
        # Close cache storage when addon is done
        self.storage.close()
