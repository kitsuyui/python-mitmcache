from __future__ import annotations

from unittest.mock import MagicMock, patch

from mitmcache.storage.factory import StorageFactory
from mitmcache.storage.sqlite3 import SQLiteStorage


def test_storage_factory_create_returns_sqlite_storage() -> None:
    """create() returns an SQLiteStorage backed by the configured cache_file."""
    factory = StorageFactory()
    with patch("mitmcache.storage.factory.ctx") as mock_ctx:
        mock_ctx.options.cache_file = ":memory:"
        storage = factory.create()
        assert isinstance(storage, SQLiteStorage)
        storage.close()


def test_storage_factory_load_registers_cache_file_option() -> None:
    """load() registers the cache_file option on the mitmproxy loader."""
    factory = StorageFactory()
    mock_loader = MagicMock()
    factory.load(mock_loader)
    mock_loader.add_option.assert_called_once_with(
        name="cache_file",
        typespec=str,
        default=":memory:",
        help="Cache file path for SQLite3 storage.",
    )
