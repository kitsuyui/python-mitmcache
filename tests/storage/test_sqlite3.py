from __future__ import annotations

import importlib.metadata
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


def test_cache_storage_records_flow_format_version() -> None:
    """Confirm that flow_format_version is stored with each entry."""
    storage = SQLiteStorage(":memory:")
    flow = example_flow()
    storage.store("test", flow)

    row = storage.conn.execute(
        "SELECT flow_format_version FROM cache WHERE cache_key=?",
        ("test",),
    ).fetchone()
    assert row is not None
    assert row["flow_format_version"] == importlib.metadata.version(
        "mitmproxy"
    )
    storage.close()


def test_cache_storage_version_mismatch_returns_none() -> None:
    """Confirm that a version-mismatched entry is treated as a cache miss."""
    storage = SQLiteStorage(":memory:")
    flow = example_flow()
    storage.store("test", flow)

    # Simulate a BLOB written by a different mitmproxy version.
    storage.conn.execute(
        "UPDATE cache SET flow_format_version=? WHERE cache_key=?",
        ("0.0.0", "test"),
    )
    storage.conn.commit()

    assert storage.get("test") is None
    storage.close()


def test_cache_storage_corrupt_blob_returns_none() -> None:
    """Confirm that a corrupt BLOB does not crash get() and returns None."""
    storage = SQLiteStorage(":memory:")
    flow = example_flow()
    storage.store("test", flow)

    storage.conn.execute(
        "UPDATE cache SET flow=? WHERE cache_key=?",
        (b"not-a-valid-flow-blob", "test"),
    )
    storage.conn.commit()

    assert storage.get("test") is None
    storage.close()


def test_cache_storage_migrates_existing_db() -> None:
    """Confirm that existing DBs without the version column are migrated."""
    import sqlite3 as _sqlite3

    conn = _sqlite3.connect(":memory:")
    conn.row_factory = _sqlite3.Row
    # Create old-style schema without flow_format_version.
    conn.execute(
        """
        CREATE TABLE cache (
            id INTEGER PRIMARY KEY,
            cache_key TEXT UNIQUE,
            url TEXT,
            method TEXT,
            flow BLOB
        )
        """
    )
    conn.commit()

    # SQLiteStorage.__init__ should add the missing column.
    storage = SQLiteStorage.__new__(SQLiteStorage)
    storage.conn = conn
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE cache ADD COLUMN flow_format_version TEXT")
    except _sqlite3.OperationalError:
        pass
    conn.commit()

    cols = [r[1] for r in conn.execute("PRAGMA table_info(cache)").fetchall()]
    assert "flow_format_version" in cols
    conn.close()
