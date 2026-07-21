# tests/test_package.py
import lkapi


def test_public_api():
    """Test the top level package exposes the documented public API."""
    for name in lkapi.__all__:
        assert getattr(lkapi, name, None) is not None, f"lkapi.{name} missing"


def test_version():
    """Test the package reports a version."""
    assert isinstance(lkapi.__version__, str)
    assert lkapi.__version__
