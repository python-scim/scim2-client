import pytest
from scim2_models import Error
from scim2_models import Resource
from scim2_models import User

from scim2_client import RequestNetworkError
from scim2_client import SCIMRequestError


class UnregisteredResource(Resource):
    schemas: list[str] = ["urn:test:schemas:UnregisteredResource"]


def test_delete_user(httpserver, sync_client):
    """Nominal case for a User deletion."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="DELETE"
    ).respond_with_data(status=204, content_type="application/scim+json")

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
    with pytest.raises(SCIMRequestError, match=r"Unknown resource type"):
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
    """Test that httpx exceptions are transformed in RequestNetworkError."""
    with pytest.raises(
        RequestNetworkError, match="Network error happened during request"
    ):
        sync_client.delete(User, "anything", url="http://invalid.test")
