# mitmcache

![Coverage](https://raw.githubusercontent.com/kitsuyui/octocov-central/main/badges/kitsuyui/python-mitmcache/coverage.svg)

mitmcache is an addon script for mitmproxy to cache HTTP/HTTPS traffic.
mitmproxy is a proxy server for HTTP/HTTPS traffic.
mitmcache is a simple cache script for mitmproxy.

This is useful for web service development, testing, debugging and web scraping.

## Usage

### Installation

mitmcache is intended to be run from this source repository and is not
currently published to PyPI.

Install the runtime and development dependencies with
[uv](https://docs.astral.sh/uv/):

```sh
$ git clone https://github.com/kitsuyui/python-mitmcache.git
$ cd python-mitmcache
$ uv sync
```

The project requires Python 3.12 or newer. After `uv sync`, run the
commands below with `uv run poe ...` from the repository root.

### Download certificate

```sh
$ uv run poe download_cert
```

It will download the certificate to `/tmp/mitm.pem`. You can change the path by adding the `--path` option.

### Start proxy

```sh
$ uv run poe proxy
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

The cache is stored in a SQLite3 database.

By default the `cache_file` option is `:memory:`, so the cache lives only
for the duration of the proxy process and is discarded on exit. To persist
the cache across restarts, pass `--set cache_file=cache.db` when starting
mitmproxy:

```sh
$ mitmdump -s inject.py --set cache_file=cache.db
```

`uv run poe proxy` already passes `--set cache_file=cache.db` so it
creates a `cache.db` file in the current directory automatically.

## Development

This repository uses [lefthook](https://lefthook.dev/) to run the same checks as CI
locally, so problems surface before they reach CI.

```sh
# Install dependencies
uv sync

# Install the Git hooks (once; requires lefthook on your PATH)
lefthook install
```

Once installed, the hooks run automatically:

- **pre-commit**: `uv run poe check`
- **pre-push**: `uv run poe check` and `uv run poe test`

You can also run the checks manually:

```sh
uv run poe check
uv run poe test
```

CI still runs the full matrix (see `.github/workflows/`); the hooks only bring that
feedback earlier on your machine.

# License

MIT License
