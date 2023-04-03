from __future__ import annotations

from typing import Any

from mitmproxy.http import HTTPFlow
from mitmproxy.io.compat import migrate_flow


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
