from __future__ import annotations

from typing import Any

import pytest
from mitmproxy.addons import script
from mitmproxy.http import HTTPFlow
from mitmproxy.io.compat import migrate_flow
from mitmproxy.test import taddons, tflow, tutils

from mitmcache.cache import get_cache_key_from_flow
from mitmcache.cache_sqlite3_storage import SQLiteCacheStorage


# This filter seems not to work
@pytest.mark.filterwarnings("ignore:'crypt' is deprecated.*?:")
def test_load_addon() -> None:
    """Confirm that the addon can be loaded."""
    script.load_script("inject.py")


def example_flow() -> HTTPFlow:
    base_unixtime = 1234567890.123456
    data: dict[bytes | str, Any] = {
        "type": "http",
        "version": 18,
        "websocket": None,
        "response": {
            "reason": b"",
            "status_code": 200,
            "timestamp_end": base_unixtime + 0.9,
            "timestamp_start": base_unixtime + 0.8,
            "trailers": None,
            "content": b"Hello, World!",
            "headers": [
                [b"content-length", b"13"],
            ],
            "http_version": b"HTTP/2.0",
        },
        "request": {
            "path": b"/",
            "authority": b"example.com",
            "scheme": b"https",
            "method": b"GET",
            "port": 443,
            "host": "example.com",
            "timestamp_end": base_unixtime + 0.7,
            "timestamp_start": base_unixtime + 0.5,
            "trailers": None,
            "content": b"",
            "headers": [
                [b"mitm-cache-key", b"1234"],
            ],
            "http_version": b"HTTP/2.0",
        },
        "timestamp_created": base_unixtime + 0.6,
        "comment": "",
        "metadata": {},
        "marked": "",
        "is_replay": None,
        "intercepted": False,
        "server_conn": {
            "via2": None,
            "cipher_list": [],
            "cipher_name": "TLS_AES_256_GCM_SHA384",
            "alpn_offers": [b"h2", b"http/1.1"],
            "certificate_list": [
                # base64 encoded certificates
                # -----BEGIN CERTIFICATE-----\n
                # ...
                # -----END CERTIFICATE-----\n
            ],
            "tls": True,
            "error": None,
            "state": 3,
            "via": None,
            "tls_version": "TLSv1.3",
            "tls_established": True,
            "timestamp_tls_setup": base_unixtime + 0.3,
            "timestamp_tcp_setup": base_unixtime + 0.2,
            "timestamp_start": base_unixtime + 0.1,
            "timestamp_end": None,
            "source_address": ["127.0.0.1", 50000],
            "sni": "example.com",
            "ip_address": ["127.0.0.1", 443],
            "id": "00000000-0000-0000-0000-222222222222",
            "alpn": b"h2",
            "address": ["example.com", 443],
        },
        "client_conn": {
            "proxy_mode": "regular",
            "cipher_list": [],
            "alpn_offers": [b"h2", b"http/1.1"],
            "certificate_list": [],
            "tls": True,
            "error": None,
            "sockname": ["127.0.0.1", 8080],
            "state": 3,
            "tls_version": "TLSv1.3",
            "tls_extensions": [],
            "tls_established": True,
            "timestamp_tls_setup": base_unixtime + 0.4,
            "timestamp_start": base_unixtime,
            "timestamp_end": None,
            "sni": "example.com",
            "mitmcert": None,
            "id": "00000000-0000-0000-0000-111111111111",
            "cipher_name": "TLS_AES_256_GCM_SHA384",
            "alpn": b"h2",
            "address": ["127.0.0.1", 50000],
        },
        "error": None,
        "id": "00000000-0000-0000-0000-000000000000",
    }
    flow = HTTPFlow.from_state(migrate_flow(data))
    return flow


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


def test_cache_storage() -> None:
    """Confirm that the cache storage can be used."""
    storage = SQLiteCacheStorage(":memory:")
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


@pytest.mark.filterwarnings("ignore:'crypt' is deprecated.*?:")
def test_cache_hit() -> None:
    """Confirm that the cache hit is processed normally.

    the request is not sent to the origin server when the cache hit.
    """
    with taddons.context() as tctx:
        addon = tctx.script("inject.py").addons[0]

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
        addon.response(flow)
        addon.done()


@pytest.mark.filterwarnings("ignore:'crypt' is deprecated.*?:")
def test_get_cache_key_from_flow() -> None:
    """Confirm that the cache key is extracted from the flow."""
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
    assert get_cache_key_from_flow(flow) == "2345"

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
    assert get_cache_key_from_flow(flow) == "3456"

    # case3. request doesn't have the cache key and response is empty
    flow = tflow.tflow(
        req=tutils.treq(
            method=b"GET",
            path=b"/",
            host=b"localhost:65535",
        ),
        resp=False,
    )
    assert get_cache_key_from_flow(flow) is None

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
    assert get_cache_key_from_flow(flow) is None
