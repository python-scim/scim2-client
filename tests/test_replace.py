import datetime

import pytest
from scim2_models import Error
from scim2_models import Group
from scim2_models import InvalidValueException
from scim2_models import Meta
from scim2_models import ResourceType
from scim2_models import SCIMException
from scim2_models import User

from scim2_client import RequestNetworkException


def test_replace_user(httpserver, sync_client):
    """Nominal case for a User creation object."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PUT"
    ).respond_with_json(
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
        content_type="application/scim+json",
    )

    user = User(
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

    response = sync_client.replace(user)
    assert response.model_dump() == user.model_dump()


def test_replace_user_dict(httpserver, sync_client):
    """Nominal case for a User creation object by passing a dict."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PUT"
    ).respond_with_json(
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
        content_type="application/scim+json",
    )

    user = User(
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

    response = sync_client.replace(user.model_dump())
    assert response.model_dump() == user.model_dump()


def test_replace_user_dict_bad_schema(httpserver, sync_client):
    """Test case for a User creation object by passing a dict with an invalid or missing schema."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PUT"
    ).respond_with_json(
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
        content_type="application/scim+json",
    )

    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Invalid"],
        "userName": "bjensen@example.com",
    }

    with pytest.raises(
        InvalidValueException, match="Cannot guess resource type from the payload"
    ):
        sync_client.replace(payload)


def test_dont_check_response_payload(httpserver, sync_client):
    """Test the check_response_payload_attribute."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PUT"
    ).respond_with_json({"foo": "bar"}, status=200)

    user = User(
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

    response = sync_client.replace(user, check_response_payload=False)
    assert response == {"foo": "bar"}


def test_dont_check_request_payload(httpserver, sync_client):
    """Test the check_request_payload_attribute.

    TODO: Actually check that the payload is sent through the network
    """
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PUT"
    ).respond_with_json(
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
        content_type="application/scim+json",
    )

    user = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "bjensen@example.com",
    }

    response = sync_client.replace(
        user,
        check_request_payload=False,
        url="/Users/2819c223-7f76-453a-919d-413861904646",
    )
    assert response == {
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


@pytest.mark.parametrize("code", [400, 401, 403, 404, 409, 412, 500, 501])
def test_errors(httpserver, code, sync_client):
    """Test error cases defined in RFC7644."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PUT"
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": str(code),
            "detail": f"{code} error",
        },
        status=code,
        content_type="application/scim+json",
    )

    user_request = User(
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

    response = sync_client.replace(user_request, raise_scim_errors=False)

    assert response == Error(
        schemas=["urn:ietf:params:scim:api:messages:2.0:Error"],
        status=code,
        detail=f"{code} error",
    )


def test_user_with_no_id(httpserver, sync_client):
    """Test that replacing an user object without and id raises an error."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PUT"
    ).respond_with_json(
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
        content_type="application/scim+json",
    )

    user = User(
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

    with pytest.raises(InvalidValueException, match="Resource must have an id"):
        sync_client.replace(user)


def test_invalid_resource_model(httpserver, sync_client):
    """Test that resource_models passed to the method must be part of SCIMClient.resource_models."""
    sync_client.resource_models = (User,)
    sync_client.resource_types = [ResourceType.from_resource(User)]

    with pytest.raises(InvalidValueException, match=r"Unknown resource type"):
        sync_client.replace(Group(display_name="foobar"))


def test_request_validation_error(httpserver, sync_client):
    """Test that incorrect input raise a SCIMException."""
    with pytest.raises(SCIMException):
        sync_client.replace(
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "active": "not-a-bool",
            }
        )


def test_request_network_error(httpserver, sync_client):
    """Test that httpx exceptions are transformed in RequestNetworkException."""
    user_request = User(user_name="bjensen@example.com", id="anything")
    with pytest.raises(
        RequestNetworkException, match="Network error happened during request"
    ):
        sync_client.replace(user_request, url="http://invalid.test")
