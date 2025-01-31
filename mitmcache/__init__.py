from mitmcache.cache import Cache  # noqa: F401

# https://packaging-guide.openastronomy.org/en/latest/advanced/versioning.html
from ._version import __version__

__all__ = [
    "Cache",
    "__version__",
]
