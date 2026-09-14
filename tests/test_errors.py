from scim2_client.errors import ExpiredCursorError
from scim2_client.errors import InvalidCountError
from scim2_client.errors import InvalidCursorError
from scim2_client.errors import SCIMRequestError


def test_invalid_cursor_error_default_message():
    exc = InvalidCursorError()
    assert exc.message == "Cursor value is invalid."
    assert str(exc) == "Cursor value is invalid."
    assert isinstance(exc, SCIMRequestError)


def test_invalid_cursor_error_custom_message():
    exc = InvalidCursorError(message="custom cursor issue")
    assert exc.message == "custom cursor issue"
    assert str(exc) == "custom cursor issue"


def test_invalid_count_error_default_message():
    exc = InvalidCountError()
    assert exc.message == "Invalid count"
    assert str(exc) == "Invalid count"
    assert isinstance(exc, SCIMRequestError)


def test_invalid_count_error_custom_message():
    exc = InvalidCountError(message="custom count issue")
    assert exc.message == "custom count issue"
    assert str(exc) == "custom count issue"


def test_expired_cursor_error_default_message():
    exc = ExpiredCursorError()
    assert exc.message == "Expired cursor"
    assert str(exc) == "Expired cursor"
    assert isinstance(exc, SCIMRequestError)


def test_expired_cursor_error_custom_message():
    exc = ExpiredCursorError(message="custom expiry issue")
    assert exc.message == "custom expiry issue"
    assert str(exc) == "custom expiry issue"


def test_cursor_and_count_errors_carry_source():
    source = {"cursor": "abc"}
    exc = InvalidCursorError(source=source)
    assert exc.source is source
