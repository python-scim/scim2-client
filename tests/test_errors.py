from scim2_models import Error
from scim2_models import UniquenessException

from scim2_client.errors import server_error_exception


def test_server_error_exception_uses_the_class_matching_the_scim_type():
    """Test that a known scimType is turned into its dedicated exception."""
    error = Error(status=409, scim_type="uniqueness", detail="User already exists")
    exc = server_error_exception(error)

    assert isinstance(exc, UniquenessException)
    assert exc.to_error() == error


def test_server_error_exception_keeps_unknown_status_and_scim_type():
    """Test that values scim2-models has no exception class for are preserved."""
    error = Error(status=429, scim_type="tooManyRequests", detail="Slow down")
    exc = server_error_exception(error)

    assert exc.status == 429
    assert exc.scim_type == "tooManyRequests"
    assert exc.to_error() == error


def test_server_error_exception_without_status():
    """Test that an error object carrying no status keeps the default one."""
    error = Error(detail="Something happened")
    exc = server_error_exception(error)

    assert exc.status == 400
    assert exc.error is error
