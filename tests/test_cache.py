from __future__ import annotations

import pytest
from mitmproxy.addons import script
from mitmproxy.test import taddons, tflow, tutils

from mitmcache.cache import get_cache_key_from_flow

from .example_flow import example_flow


# This filter seems not to work
@pytest.mark.filterwarnings("ignore:'crypt' is deprecated.*?:")
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
