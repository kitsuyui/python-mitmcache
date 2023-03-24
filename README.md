# mitmcache

mitmcache is an addon script for mitmproxy to cache HTTP/HTTPS traffic.
mitmproxy is a proxy server for HTTP/HTTPS traffic.
mitmcache is a simple cache script for mitmproxy.

This is useful for web service development, testing, debugging and web scraping.

## Usage

### Installation

Work in progress.

### Download certificate

```sh
$ poetry poe download_cert
```

It will download the certificate to `/tmp/mitm.pem`. You can change the path by adding the `--path` option.

### Start proxy

```sh
$ poetry poe proxy
```

## Example

Normally, if you access the unixtime.jp site, the current UNIX timestamp is displayed. (Thanks to @yosida95)

```
$ curl https://unixtime.jp/
1234567890 # Note: It changes every second
```

If you start mitmcache and access unixtime.jp, the cached result will be returned.
If you access with the `mitm-cache-key` header, it will be cached with that key.

```sh
$ curl --cacert /tmp/mitm.pem -H 'mitm-cache-key: 1234' -x 127.0.0.1:8080 https://unixtime.jp/
1234567890  # The same mitm-cache-key will return the same result
```

## Cache storage

The cache is stored in a SQLite3 database (cache.db).

By default, cache.db is created in the same directory as mitmcache.py.
This behavior may change in the future.

# License

MIT License
