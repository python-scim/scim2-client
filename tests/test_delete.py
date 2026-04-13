import pytest
from scim2_models import Error
from scim2_models import Meta
from scim2_models import Resource
from scim2_models import ServiceProviderConfig
from scim2_models import User
from scim2_models.resources.service_provider_config import ETag

from scim2_client import RequestNetworkError
from scim2_client import SCIMRequestError


class UnregisteredResource(Resource):
    __schema__ = "urn:test:schemas:UnregisteredResource"


def test_delete_user(httpserver, sync_client, user):
    """Nominal case for a User deletion."""
    httpserver.expect_request(f"/Users/{user.id}", method="DELETE").respond_with_data(
        status=204, content_type="application/scim+json"
    )

    response = sync_client.delete(user)
    assert response is None


def test_delete_user_without_content_type_header(httpserver, sync_client, user):
    """Server returns 204 without Content-Type header, which is valid per RFC 7231."""
    httpserver.expect_request(f"/Users/{user.id}", method="DELETE").respond_with_data(
        status=204
    )

    response = sync_client.delete(user)
    assert response is None


@pytest.mark.parametrize("code", [400, 401, 403, 404, 412, 500, 501])
def test_errors(httpserver, code, sync_client, user):
    """Test error cases defined in RFC7644."""
    httpserver.expect_request(f"/Users/{user.id}", method="DELETE").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": str(code),
            "detail": f"{code} error",
        },
        status=code,
    )

    response = sync_client.delete(user, raise_scim_errors=False)

    assert response == Error(
        schemas=["urn:ietf:params:scim:api:messages:2.0:Error"],
        status=code,
        detail=f"{code} error",
    )


def test_delete_resource_without_id(sync_client):
    """Deleting a resource without an id raises an error."""
    no_id_user = User(user_name="no-id")
    with pytest.raises(SCIMRequestError, match="Resource must have an id"):
        sync_client.delete(no_id_user)


def test_invalid_resource_model(httpserver, sync_client):
    """Test that resource_models passed to the method must be part of SCIMClient.resource_models."""
    unregistered = UnregisteredResource()
    unregistered.id = "foobar"
    with pytest.raises(SCIMRequestError, match=r"Unknown resource type"):
        sync_client.delete(unregistered)


def test_dont_check_response_payload(httpserver, sync_client, user):
    """Test the check_response_payload attribute."""
    httpserver.expect_request(f"/Users/{user.id}", method="DELETE").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "404",
            "detail": "404 error",
        },
        status=404,
    )

    response = sync_client.delete(user, check_response_payload=False)
    assert response == {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": "404",
        "detail": "404 error",
    }


def test_request_network_error(httpserver, sync_client, user):
    """Test that httpx exceptions are transformed in RequestNetworkError."""
    with pytest.raises(
        RequestNetworkError, match="Network error happened during request"
    ):
        sync_client.delete(user, url="http://invalid.test")


def test_delete_sends_if_match(httpserver, sync_client):
    """If-Match header is sent when deleting a resource with ETag support."""
    sync_client.service_provider_config = ServiceProviderConfig(
        etag=ETag(supported=True)
    )
    user = User(
        user_name="bjensen@example.com",
        meta=Meta(version='W/"3694e05e9dff590"'),
    )
    user.id = "2819c223-7f76-453a-919d-413861904646"

    httpserver.expect_request(
        f"/Users/{user.id}",
        method="DELETE",
        headers={"If-Match": 'W/"3694e05e9dff590"'},
    ).respond_with_data(status=204, content_type="application/scim+json")

    response = sync_client.delete(user)
    assert response is None


def test_delete_no_if_match_without_etag_support(httpserver, sync_client, user):
    """No If-Match header when the server does not support ETags."""
    httpserver.expect_request(f"/Users/{user.id}", method="DELETE").respond_with_data(
        status=204, content_type="application/scim+json"
    )

    response = sync_client.delete(user)
    assert response is None
