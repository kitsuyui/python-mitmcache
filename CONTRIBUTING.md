# Contributing

Thank you for taking the time to improve mitmcache.

## Development setup

This project uses [uv](https://docs.astral.sh/uv/) for Python dependency
management and [Poe the Poet](https://poethepoet.natn.io/) for common tasks.

```sh
uv sync
```

## Checks

Run the formatter before opening a pull request:

```sh
uv run poe format
```

Run lint checks:

```sh
uv run poe check
```

Run type checks:

```sh
uv run poe typecheck
```

Run the test suite:

```sh
uv run poe test
```

## Pull requests

Before opening a pull request, please make sure that:

- the change is focused on one topic;
- relevant tests or checks pass locally;
- README or documentation updates are included when behavior changes.

When reporting a failing check, include the command you ran and the relevant
error output.
