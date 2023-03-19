import pytest
from mitmproxy.addons import script


# This filter seems not to work
@pytest.mark.filterwarnings("ignore:'crypt' is deprecated.*?:")
def test_load_addon() -> None:
    """Confirm that the addon can be loaded."""
    script.load_script("inject.py")
