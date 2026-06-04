from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mitmcache.storage.sqlite3 import SQLiteStorage

from ..example_flow import example_flow


def test_cache_storage() -> None:
    """Confirm that the cache storage can be used."""
    storage = SQLiteStorage(":memory:")
    flow = example_flow()
    storage.store("test", flow)
    cache = storage.get("test")
    assert cache is not None
    assert cache.response is not None
    assert cache.response.status_code == 200
    assert cache.response.text == "Hello, World!"
    storage.purge("test")
    assert storage.get("test") is None
    storage.close()


def test_sqlite_storage_closes_connection_on_init_failure() -> None:
    mock_conn = MagicMock()
    mock_conn.cursor.return_value.execute.side_effect = Exception(
        "init failure"
    )
    with patch(
        "mitmcache.storage.sqlite3.sqlite3.connect", return_value=mock_conn
    ):
        with pytest.raises(Exception, match="init failure"):
            SQLiteStorage(":memory:")
    mock_conn.close.assert_called_once()


def test_cache_storage_keeps_request_metadata_order() -> None:
    """Confirm that URL and method are stored in their schema columns."""
    storage = SQLiteStorage(":memory:")
    flow = example_flow()
    storage.store("test", flow)

    row = storage.conn.execute(
        "SELECT url, method FROM cache WHERE cache_key=?",
        ("test",),
    ).fetchone()
    assert row is not None
    assert row["url"] == flow.request.url
    assert row["method"] == flow.request.method

    flow.request.method = "POST"
    flow.request.url = "https://example.com/updated"
    storage.update("test", flow)

    row = storage.conn.execute(
        "SELECT url, method FROM cache WHERE cache_key=?",
        ("test",),
    ).fetchone()
    assert row is not None
    assert row["url"] == flow.request.url
    assert row["method"] == flow.request.method
    storage.close()
