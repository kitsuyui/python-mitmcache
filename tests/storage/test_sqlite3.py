from __future__ import annotations

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


def test_max_entries_evicts_oldest_on_store() -> None:
    """Oldest entries are removed when max_entries is exceeded."""
    storage = SQLiteStorage(":memory:", max_entries=2)
    flow = example_flow()
    storage.store("key1", flow)
    storage.store("key2", flow)
    storage.store("key3", flow)

    assert storage.get("key1") is None
    assert storage.get("key2") is not None
    assert storage.get("key3") is not None
    storage.close()


def test_max_entries_zero_means_unlimited() -> None:
    """max_entries=None keeps all entries (default unlimited behaviour)."""
    storage = SQLiteStorage(":memory:", max_entries=None)
    flow = example_flow()
    for i in range(10):
        storage.store(f"key{i}", flow)

    count = storage.conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
    assert count == 10
    storage.close()


def test_update_refreshes_eviction_order() -> None:
    """update() must refresh last_accessed_at so that updated entries are not evicted first.

    With max_entries=2 and three distinct store operations, the entry updated
    most recently should survive eviction while the untouched entry is dropped.
    """
    storage = SQLiteStorage(":memory:", max_entries=2)
    flow = example_flow()
    storage.store("key1", flow)
    storage.store("key2", flow)
    # key1 and key2 are now both present (at capacity).
    # Update key1 — this refreshes its last_accessed_at to "now".
    storage.update("key1", flow)
    # Store key3 — eviction runs; key2 (least recently accessed) should be evicted.
    storage.store("key3", flow)

    assert storage.get("key2") is None, (
        "key2 should have been evicted (least recently used)"
    )
    assert storage.get("key1") is not None, (
        "key1 should survive (updated recently)"
    )
    assert storage.get("key3") is not None, "key3 should survive (just stored)"
    storage.close()


def test_get_refreshes_eviction_order() -> None:
    """get() must refresh last_accessed_at so that accessed entries are not evicted first."""
    storage = SQLiteStorage(":memory:", max_entries=2)
    flow = example_flow()
    storage.store("key1", flow)
    storage.store("key2", flow)
    # Access key1 — this refreshes its last_accessed_at.
    assert storage.get("key1") is not None
    # Store key3 — eviction runs; key2 (least recently accessed) should be evicted.
    storage.store("key3", flow)

    assert storage.get("key2") is None, (
        "key2 should have been evicted (least recently accessed)"
    )
    assert storage.get("key1") is not None, (
        "key1 should survive (recently accessed)"
    )
    assert storage.get("key3") is not None, "key3 should survive (just stored)"
    storage.close()
