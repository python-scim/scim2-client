import datetime

import pytest
from scim2_models import Error
from scim2_models import Meta
from scim2_models import Resource
from scim2_models import User

from scim2_client import RequestNetworkError
from scim2_client import RequestPayloadValidationError
from scim2_client import SCIMClientError
from scim2_client import SCIMRequestError
from scim2_client import UnexpectedStatusCode


def test_create_user(httpserver, sync_client):
    """Nominal case for a User creation object."""
    httpserver.expect_request("/Users", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
            },
        },
        status=201,
    )

    user_request = User(user_name="bjensen@example.com")
    response = sync_client.create(user_request)

    user_created = User(
        id="2819c223-7f76-453a-919d-413861904646",
        user_name="bjensen@example.com",
        meta=Meta(
            resource_type="User",
            created=datetime.datetime(
                2010, 1, 23, 4, 56, 22, tzinfo=datetime.timezone.utc
            ),
            last_modified=datetime.datetime(
                2011, 5, 13, 4, 42, 34, tzinfo=datetime.timezone.utc
            ),
            version='W\\/"3694e05e9dff590"',
            location="https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
        ),
    )
    assert response == user_created


def test_create_dict_user(httpserver, sync_client):
    """Nominal case for a User creation object, when passing a dict instead of a resource."""
    httpserver.expect_request("/Users", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
            },
        },
        status=201,
    )

    user_request = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "bjensen@example.com",
    }

    response = sync_client.create(user_request)

    user_created = User(
        id="2819c223-7f76-453a-919d-413861904646",
        user_name="bjensen@example.com",
        meta=Meta(
            resource_type="User",
            created=datetime.datetime(
                2010, 1, 23, 4, 56, 22, tzinfo=datetime.timezone.utc
            ),
            last_modified=datetime.datetime(
                2011, 5, 13, 4, 42, 34, tzinfo=datetime.timezone.utc
            ),
            version='W\\/"3694e05e9dff590"',
            location="https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
        ),
    )
    assert response == user_created


def test_create_dict_user_bad_schema(httpserver, sync_client):
    """Test when passing a resource dict with an unknown or invalid schema."""
    httpserver.expect_request("/Users", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
            },
        },
        status=201,
    )

    user_request = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Invalid"],
        "userName": "bjensen@example.com",
    }

    with pytest.raises(
        SCIMClientError, match="Cannot guess resource type from the payload"
    ):
        sync_client.create(user_request)


def test_dont_check_response_payload(httpserver, sync_client):
    """Test the check_response_payload_attribute."""
    httpserver.expect_request("/Users", method="POST").respond_with_json(
        {"foo": "bar"}, status=201
    )

    user_request = User(user_name="bjensen@example.com")

    response = sync_client.create(resource=user_request, check_response_payload=False)
    assert response == {"foo": "bar"}


def test_dont_check_request_payload(httpserver, sync_client):
    """Test the check_request_payload_attribute.

    TODO: Actually check that the payload is sent through the network
    """
    httpserver.expect_request("/Users", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
            },
        },
        status=201,
    )

    user_request = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "bjensen@example.com",
    }

    response = sync_client.create(
        resource=user_request, check_request_payload=False, url="/Users"
    )

    user_created = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": "2819c223-7f76-453a-919d-413861904646",
        "userName": "bjensen@example.com",
        "meta": {
            "resourceType": "User",
            "created": "2010-01-23T04:56:22Z",
            "lastModified": "2011-05-13T04:42:34Z",
            "version": 'W\\/"3694e05e9dff590"',
            "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
        },
    }
    assert response == user_created


def test_conflict(httpserver, sync_client):
    """Nominal case for a User creation object."""
    httpserver.expect_request("/Users", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "409",
            "scimType": "uniqueness",
            "detail": "One or more of the attribute values are already in use or are reserved.",
        },
        status=409,
    )

    user_request = User(user_name="bjensen@example.com")

    response = sync_client.create(user_request, raise_scim_errors=False)
    assert response == Error(
        schemas=["urn:ietf:params:scim:api:messages:2.0:Error"],
        status=409,
        scim_type="uniqueness",
        detail="One or more of the attribute values are already in use or are reserved.",
    )


def test_no_200(httpserver, sync_client):
    """User creation object should return 201 codes and no 200."""
    httpserver.expect_request("/Users", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
            },
        },
        status=200,
    )

    user_request = User(user_name="bjensen@example.com")

    with pytest.raises(UnexpectedStatusCode):
        sync_client.create(user_request)
    sync_client.create(user_request, expected_status_codes=None)
    sync_client.create(user_request, expected_status_codes=[200, 201])


@pytest.mark.parametrize("code", [400, 401, 403, 404, 500])
def test_errors(httpserver, code, sync_client):
    """Test error cases defined in RFC7644."""
    httpserver.expect_request("/Users", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": str(code),
            "detail": f"{code} error",
        },
        status=code,
    )

    user_request = User(user_name="bjensen@example.com")

    response = sync_client.create(user_request, raise_scim_errors=False)

    assert response == Error(
        schemas=["urn:ietf:params:scim:api:messages:2.0:Error"],
        status=code,
        detail=f"{code} error",
    )


def test_invalid_resource_model(sync_client):
    """Test that resource_models passed to the method must be part of SCIMClient.resource_models."""

    class MyResource(Resource):
        __schema__ = "urn:ietf:params:scim:schemas:core:2.0:MyResource"
        display_name: str | None = None

    with pytest.raises(SCIMRequestError, match=r"Unknown resource type"):
        sync_client.create(MyResource(display_name="foobar"))


def test_request_validation_error(sync_client):
    """Test that incorrect input raise a RequestPayloadValidationError."""
    with pytest.raises(
        RequestPayloadValidationError, match="Server request payload validation error"
    ):
        sync_client.create(
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "active": "not-a-bool",
            }
        )


def test_request_network_error(sync_client):
    """Test that httpx exceptions are transformed in RequestNetworkError."""
    user_request = User(user_name="bjensen@example.com")
    with pytest.raises(
        RequestNetworkError, match="Network error happened during request"
    ):
        sync_client.create(user_request, url="http://invalid.test")
