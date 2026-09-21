import pytest
from scim2_models import User

import scim2_client
from scim2_client import errors

RENAMED_EXCEPTIONS = [
    ("SCIMClientError", "SCIMClientException"),
    ("SCIMResponseError", "SCIMResponseException"),
    ("RequestNetworkError", "RequestNetworkException"),
    ("UnexpectedStatusCode", "UnexpectedStatusCodeException"),
    ("UnexpectedContentType", "UnexpectedContentTypeException"),
    ("UnexpectedContentFormat", "UnexpectedContentFormatException"),
    ("ResponsePayloadValidationError", "ResponsePayloadValidationException"),
]


@pytest.mark.parametrize(("old", "new"), RENAMED_EXCEPTIONS)
@pytest.mark.parametrize("module", [scim2_client, errors])
def test_old_exception_names_are_the_renamed_classes(module, old, new):
    """Test that the old exception names warn about the rename and point at the new classes."""
    with pytest.warns(DeprecationWarning, match=f"{old} is deprecated, use {new}"):
        alias = getattr(module, old)

    assert alias is getattr(module, new)


@pytest.mark.parametrize("module", [scim2_client, errors])
def test_unknown_names_are_not_served(module):
    """Test that names that were never part of the API are still unknown."""
    unknown_name = "Foobar"
    with pytest.raises(AttributeError, match="has no attribute 'Foobar'"):
        getattr(module, unknown_name)


def test_old_exception_names_catch_the_exceptions_the_client_raises(
    httpserver, sync_client
):
    """Test that code written against the old names still catches the client exceptions."""
    httpserver.expect_request("/Users").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
        },
        status=299,
    )

    with pytest.warns(DeprecationWarning):
        unexpected_status_code = errors.UnexpectedStatusCode

    with pytest.raises(unexpected_status_code):
        sync_client.create(User(user_name="bjensen@example.com"))
