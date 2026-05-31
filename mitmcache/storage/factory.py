"""Factory of Storage

There are many Storage classes, such as
- SQLiteStorage
- RedisStorage
- FileStorage
- etc.

StorageFactory knows how to initialize them.
So, the user of Storage does not need to know how to initialize them.
"""

from __future__ import annotations

import logging

from mitmproxy import ctx
from mitmproxy.addonmanager import Loader

from .cache_storage import CacheStorage
from .sqlite3 import SQLiteStorage

logger = logging.getLogger(__name__)


class StorageFactory:
    def create(self) -> CacheStorage:
        try:
            raw = int(ctx.options.cache_max_entries)
        except (ValueError, TypeError):
            logger.warning(
                "cache_max_entries is not a valid integer; defaulting to unlimited."
            )
            raw = 0
        max_entries = raw if raw > 0 else None
        return SQLiteStorage(ctx.options.cache_file, max_entries=max_entries)

    def load(self, loader: Loader) -> None:
        loader.add_option(
            name="cache_file",
            typespec=str,
            default=":memory:",
            help="Cache file path for SQLite3 storage.",
        )
        loader.add_option(
            name="cache_max_entries",
            typespec=int,
            default=0,
            help="Maximum number of entries in the SQLite cache. 0 = unlimited.",
        )
