import pytest

from scim2_client.errors import RequestNetworkError
from scim2_client.errors import ResponsePayloadValidationError
from scim2_client.errors import SCIMClientError
from scim2_client.errors import SCIMResponseError
from scim2_client.errors import UnexpectedContentFormat
from scim2_client.errors import UnexpectedContentType
from scim2_client.errors import UnexpectedStatusCode


def test_scim_client_error_deprecation():
    """Test that SCIMClientError emits a deprecation warning."""
    with pytest.warns(DeprecationWarning, match="SCIMClientError is deprecated"):
        SCIMClientError("test")


def test_scim_response_error_deprecation():
    """Test that SCIMResponseError emits a deprecation warning."""
    with pytest.warns(DeprecationWarning, match="SCIMResponseError is deprecated"):
        SCIMResponseError("test")


def test_request_network_error_deprecation():
    """Test that RequestNetworkError emits a deprecation warning."""
    with pytest.warns(DeprecationWarning, match="RequestNetworkError is deprecated"):
        RequestNetworkError()


def test_unexpected_status_code_deprecation():
    """Test that UnexpectedStatusCode emits a deprecation warning."""
    with pytest.warns(DeprecationWarning, match="UnexpectedStatusCode is deprecated"):
        UnexpectedStatusCode(404)


def test_unexpected_content_type_deprecation():
    """Test that UnexpectedContentType emits a deprecation warning."""
    with pytest.warns(DeprecationWarning, match="UnexpectedContentType is deprecated"):
        UnexpectedContentType("text/html")


def test_unexpected_content_format_deprecation():
    """Test that UnexpectedContentFormat emits a deprecation warning."""
    with pytest.warns(
        DeprecationWarning, match="UnexpectedContentFormat is deprecated"
    ):
        UnexpectedContentFormat()


def test_response_payload_validation_error_deprecation():
    """Test that ResponsePayloadValidationError emits a deprecation warning."""
    with pytest.warns(
        DeprecationWarning, match="ResponsePayloadValidationError is deprecated"
    ):
        ResponsePayloadValidationError()
