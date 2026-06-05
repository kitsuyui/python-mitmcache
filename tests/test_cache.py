from __future__ import annotations

from mitmproxy.addons import script
from mitmproxy.test import taddons, tflow, tutils

from mitmcache.cache import Cache, _sanitize_for_log
from mitmcache.storage.cache_storage import CacheStorage

from .example_flow import example_flow


class TrackingStorage:
    def __init__(self, storage: CacheStorage) -> None:
        self.storage = storage
        self.store_count = 0
        self.update_count = 0
        self.upsert_count = 0

    def get(self, cache_key):
        return self.storage.get(cache_key)

    def store(self, cache_key, flow):
        self.store_count += 1
        self.storage.store(cache_key, flow)

    def update(self, cache_key, flow):
        self.update_count += 1
        self.storage.update(cache_key, flow)

    def upsert(self, cache_key, flow):
        self.upsert_count += 1
        self.storage.upsert(cache_key, flow)

    def purge(self, cache_key):
        self.storage.purge(cache_key)

    def close(self):
        self.storage.close()


def test_done_before_configure_no_error() -> None:
    """done() must not raise AttributeError when called before configure().

    mitmproxy may call done() on early teardown before configure() ever runs.
    Without a guard, self.storage is unset and the unconditional
    self.storage.close() raises AttributeError.
    """
    addon = Cache()
    addon.done()  # must not raise


def test_load_addon() -> None:
    """Confirm that the addon can be loaded."""
    script.load_script("inject.py")


def test_simple() -> None:
    with taddons.context() as tctx:
        # Confirm that the request unrelated to the cache is processed normally
        addon = tctx.script("inject.py").addons[0]

        flow = tflow.tflow(
            req=tutils.treq(method=b"GET"),
            resp=tutils.tresp(content=b"Hello, World!"),
        )
        addon.request(flow)
        addon.response(flow)

        # Confirm that the request related to the cache is processed normally
        flow = example_flow()
        addon.request(flow)
        addon.response(flow)
        addon.done()


def test_cache_hit() -> None:
    """Confirm that the cache hit is processed normally.

    the request is not sent to the origin server when the cache hit.
    """
    with taddons.context() as tctx:
        addon = tctx.script("inject.py").addons[0]
        storage = TrackingStorage(addon.storage)
        addon.storage = storage

        flow = tflow.tflow(
            req=tutils.treq(
                method=b"GET",
                path=b"/",
                host=b"localhost:65535",  # It doesn't listen really
                headers=[(b"Mitm-Cache-Key", b"1234")],
            ),
            resp=tutils.tresp(
                content=b"Hello, World!",
                status_code=200,
            ),
        )
        # cache miss but the response is stored
        addon.request(flow)
        addon.response(flow)
        assert storage.upsert_count == 1

        flow = tflow.tflow(
            req=tutils.treq(
                method=b"GET",
                path=b"/",
                host=b"localhost:65535",  # It doesn't listen really
                headers=[(b"Mitm-Cache-Key", b"1234")],
            ),
            resp=False,
        )
        # cache hit
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 200
        assert flow.response.text == "Hello, World!"
        assert flow.metadata[addon.cache_from_origin] is False
        addon.response(flow)
        assert storage.upsert_count == 1
        addon.done()


def test_configure_closes_previous_storage() -> None:
    """Confirm that reconfiguring closes the previous storage."""
    with taddons.context() as tctx:
        addon = tctx.script("inject.py").addons[0]
        previous = TrackingStorage(addon.storage)
        addon.storage = previous
        previous.close_count = 0

        original_close = previous.close

        def tracked_close() -> None:
            previous.close_count += 1
            original_close()

        previous.close = tracked_close  # type: ignore[method-assign]

        # Re-applying configure with cache_file in the updated set should
        # close the previous storage and create a fresh one.
        addon.configure({"cache_file"})
        assert previous.close_count == 1
        assert addon.storage is not previous

        # configure with an unrelated option should not recreate storage.
        current = addon.storage
        addon.configure({"cache_key"})
        assert addon.storage is current

        # configure with cache_max_entries must recreate storage so the new
        # value takes effect.
        addon.configure({"cache_max_entries"})
        assert addon.storage is not current

        addon.done()


def test_cache_key_header_stripped_before_origin() -> None:
    """`Mitm-Cache-Key` request header must not leak to the origin server.

    Covers cache miss (storage returns None) and the no-cache-key path. The
    cache hit case is already exercised by `test_cache_hit`; the request is
    short-circuited there so no origin call happens regardless.
    """
    with taddons.context() as tctx:
        addon = tctx.script("inject.py").addons[0]

        # case1. cache key supplied but cache miss -> request is forwarded
        # to origin, header must be stripped first.
        flow_miss = tflow.tflow(
            req=tutils.treq(
                method=b"GET",
                path=b"/",
                host=b"localhost:65535",
                headers=[(b"Mitm-Cache-Key", b"miss-key")],
            ),
            resp=False,
        )
        addon.request(flow_miss)
        assert flow_miss.response is None
        assert addon.cache_key not in flow_miss.request.headers
        assert flow_miss.metadata[addon.cache_key] == "miss-key"

        # case2. no cache key -> auto-uuid path, header should be absent
        # before forwarding to origin.
        flow_nokey = tflow.tflow(
            req=tutils.treq(
                method=b"GET",
                path=b"/",
                host=b"localhost:65535",
            ),
            resp=False,
        )
        addon.request(flow_nokey)
        assert addon.cache_key not in flow_nokey.request.headers

        addon.done()


def test_request_and_response_after_done_are_no_ops() -> None:
    """request() and response() called after done() must not raise.

    Verifies the CLOSED state guard introduced to prevent
    sqlite3.ProgrammingError when mitmproxy calls hooks after done().
    """
    with taddons.context() as tctx:
        addon = tctx.script("inject.py").addons[0]
        storage = TrackingStorage(addon.storage)
        addon.storage = storage

        addon.done()
        assert addon._closed is True

        flow = tflow.tflow(
            req=tutils.treq(
                method=b"GET",
                path=b"/",
                host=b"localhost:65535",
                headers=[(b"Mitm-Cache-Key", b"key1")],
            ),
            resp=tutils.tresp(content=b"body"),
        )
        # Neither call should raise or touch storage.
        addon.request(flow)
        addon.response(flow)
        assert storage.store_count == 0
        assert storage.update_count == 0

        # configure() reopens storage and clears the closed flag.
        addon.configure({"cache_file"})
        assert addon._closed is False


def test_cache_key_header_not_leaked_to_client() -> None:
    """Internal cache key header must not appear in the response seen by clients.

    On a cache hit, the addon must not expose the proxy-internal
    header to downstream consumers.
    """
    with taddons.context() as tctx:
        addon = tctx.script("inject.py").addons[0]

        # First request: populate the cache.
        flow_store = tflow.tflow(
            req=tutils.treq(
                method=b"GET",
                path=b"/",
                host=b"localhost:65535",
                headers=[(b"Mitm-Cache-Key", b"leak-test-key")],
            ),
            resp=tutils.tresp(
                content=b"Cached body",
                status_code=200,
            ),
        )
        addon.request(flow_store)
        addon.response(flow_store)

        # Second request: cache hit.
        flow_hit = tflow.tflow(
            req=tutils.treq(
                method=b"GET",
                path=b"/",
                host=b"localhost:65535",
                headers=[(b"Mitm-Cache-Key", b"leak-test-key")],
            ),
            resp=False,
        )
        addon.request(flow_hit)
        assert flow_hit.response is not None
        addon.response(flow_hit)

        # The internal header must not be present in the response forwarded to
        # the client.
        assert addon.cache_key not in flow_hit.response.headers

        addon.done()


def test_get_cache_key_from_flow() -> None:
    """Confirm that the cache key is extracted from the flow."""
    with taddons.context() as tctx:
        addon = tctx.script("inject.py").addons[0]

        # case1. response is empty
        flow = tflow.tflow(
            req=tutils.treq(
                method=b"GET",
                path=b"/",
                host=b"localhost:65535",
                headers=[(b"Mitm-Cache-Key", b"2345")],
            ),
            resp=False,
        )
        assert addon.get_cache_key_from_flow(flow) == "2345"

        # case2. request doesn't have the cache key but response has it
        flow = tflow.tflow(
            req=tutils.treq(
                method=b"GET",
                path=b"/",
                host=b"localhost:65535",
            ),
            resp=tutils.tresp(
                content=b"Hello, World!",
                status_code=200,
                headers=[(b"Mitm-Cache-Key", b"3456")],
            ),
        )
        assert addon.get_cache_key_from_flow(flow) == "3456"

        # case3. request doesn't have the cache key and response is empty
        flow = tflow.tflow(
            req=tutils.treq(
                method=b"GET",
                path=b"/",
                host=b"localhost:65535",
            ),
            resp=False,
        )
        assert addon.get_cache_key_from_flow(flow) is None

        # case4. request and response don't have the cache key
        flow = tflow.tflow(
            req=tutils.treq(
                method=b"GET",
                path=b"/",
                host=b"localhost:65535",
            ),
            resp=tutils.tresp(
                content=b"Hello, World!",
                status_code=200,
            ),
        )
        assert addon.get_cache_key_from_flow(flow) is None

        # case5. empty header value is a valid cache key (not silently skipped)
        flow = tflow.tflow(
            req=tutils.treq(
                method=b"GET",
                path=b"/",
                host=b"localhost:65535",
                headers=[(b"Mitm-Cache-Key", b"")],
            ),
            resp=False,
        )
        assert addon.get_cache_key_from_flow(flow) == ""

        addon.done()


def test_sanitize_for_log() -> None:
    """Control characters in cache keys must be escaped before logging."""
    assert _sanitize_for_log("normal-key") == "normal-key"
    assert _sanitize_for_log("key\nINFO fake") == "key\\x0aINFO fake"
    assert _sanitize_for_log("key\r\n") == "key\\x0d\\x0a"
    assert _sanitize_for_log("\x1b[31mred\x1b[0m") == "\\x1b[31mred\\x1b[0m"
    assert _sanitize_for_log("") == ""
