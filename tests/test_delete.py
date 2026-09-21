import pytest
from scim2_models import Error
from scim2_models import InvalidValueException
from scim2_models import Resource
from scim2_models import User

from scim2_client import RequestNetworkException


class UnregisteredResource(Resource):
    __schema__ = "urn:test:schemas:UnregisteredResource"


def test_delete_user(httpserver, sync_client):
    """Nominal case for a User deletion."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="DELETE"
    ).respond_with_data(status=204, content_type="application/scim+json")

    response = sync_client.delete(User, "2819c223-7f76-453a-919d-413861904646")
    assert response is None


def test_delete_user_without_content_type_header(httpserver, sync_client):
    """Server returns 204 without Content-Type header, which is valid per RFC 7231."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="DELETE"
    ).respond_with_data(status=204)

    response = sync_client.delete(User, "2819c223-7f76-453a-919d-413861904646")
    assert response is None


@pytest.mark.parametrize("code", [400, 401, 403, 404, 412, 500, 501])
def test_errors(httpserver, code, sync_client):
    """Test error cases defined in RFC7644."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="DELETE"
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": str(code),
            "detail": f"{code} error",
        },
        status=code,
    )

    response = sync_client.delete(
        User, "2819c223-7f76-453a-919d-413861904646", raise_scim_errors=False
    )

    assert response == Error(
        schemas=["urn:ietf:params:scim:api:messages:2.0:Error"],
        status=code,
        detail=f"{code} error",
    )


def test_invalid_resource_model(httpserver, sync_client):
    """Test that resource_models passed to the method must be part of SCIMClient.resource_models."""
    with pytest.raises(InvalidValueException, match=r"Unknown resource type"):
        sync_client.delete(UnregisteredResource, id="foobar")


def test_dont_check_response_payload(httpserver, sync_client):
    """Test the check_response_payload attribute."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="DELETE"
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "404",
            "detail": "404 error",
        },
        status=404,
    )

    response = sync_client.delete(
        User, "2819c223-7f76-453a-919d-413861904646", check_response_payload=False
    )
    assert response == {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": "404",
        "detail": "404 error",
    }


def test_request_network_error(httpserver, sync_client):
    """Test that httpx2 exceptions are transformed in RequestNetworkException."""
    with pytest.raises(
        RequestNetworkException, match="Network error happened during request"
    ):
        sync_client.delete(User, "anything", url="http://invalid.test")


def test_delete_resource_object(httpserver, sync_client, user):
    """A resource object designates the resource with the same id."""
    httpserver.expect_request(f"/Users/{user.id}", method="DELETE").respond_with_data(
        status=204, content_type="application/scim+json"
    )

    assert sync_client.delete(user) is None


def test_delete_resource_object_without_id(sync_client):
    """A resource object without an id cannot designate a resource."""
    with pytest.raises(InvalidValueException, match="Resource must have an id"):
        sync_client.delete(User(user_name="bjensen@example.com"))


def test_delete_resource_object_and_id(sync_client, user):
    """A resource object already carries an id, so passing both is ambiguous."""
    with pytest.raises(
        InvalidValueException, match="Cannot pass both a resource object and an id"
    ):
        sync_client.delete(user, "another-id")


def test_delete_resource_type_without_id(sync_client):
    """A resource type alone does not designate a resource."""
    with pytest.raises(InvalidValueException, match="Resource must have an id"):
        sync_client.delete(User)


def test_delete_without_target(sync_client):
    """Nothing to delete when neither a resource nor a type is given."""
    with pytest.raises(InvalidValueException, match="No resource type to delete"):
        sync_client.delete()
