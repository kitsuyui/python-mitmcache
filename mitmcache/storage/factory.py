"""Factory for Storage initialization.

Currently only SQLiteStorage is supported.
StorageFactory initializes it from mitmproxy options, so callers do not
need to know the constructor details.
"""

from __future__ import annotations

from mitmproxy import ctx
from mitmproxy.addonmanager import Loader

from .cache_storage import CacheStorage
from .sqlite3 import SQLiteStorage


class StorageFactory:
    def create(self) -> CacheStorage:
        return SQLiteStorage(ctx.options.cache_file)

    def load(self, loader: Loader) -> None:
        loader.add_option(
            name="cache_file",
            typespec=str,
            default=":memory:",
            help="Cache file path for SQLite3 storage.",
        )
