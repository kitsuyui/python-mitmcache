from __future__ import annotations

from typing import get_protocol_members

from mitmcache.storage.cache_storage import CacheStorage
from mitmcache.storage.sqlite3 import SQLiteStorage


def test_sqlite_storage_satisfies_cache_storage_protocol() -> None:
    """SQLiteStorage must implement all methods required by CacheStorage."""
    required = get_protocol_members(CacheStorage)
    missing = required - set(dir(SQLiteStorage))
    assert not missing, (
        f"SQLiteStorage is missing CacheStorage methods: {missing}"
    )
