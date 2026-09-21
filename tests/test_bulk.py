import pytest
from scim2_models import BulkOperation
from scim2_models import BulkRequest
from scim2_models import BulkResponse
from scim2_models import Error
from scim2_models import Group
from scim2_models import GroupMember
from scim2_models import User

from scim2_client import RequestNetworkException


def test_bulk_request(httpserver, sync_client):
    """Test that a bulk request is posted and its response is validated."""
    httpserver.expect_request("/Bulk", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],
            "Operations": [
                {
                    "location": "https://example.com/v2/Users/92b725cd-9465-4e7d-8c16-01f8e146b87a",
                    "method": "POST",
                    "bulkId": "qwerty",
                    "version": 'W/"4weymrEsh5O6cAEK"',
                    "status": "201",
                },
                {
                    "location": "https://example.com/v2/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a",
                    "method": "POST",
                    "bulkId": "ytrewq",
                    "version": 'W/"lha5bbazU3fNvfe5"',
                    "status": "201",
                },
            ],
        },
        status=200,
    )
    req = BulkRequest[User | Group](
        operations=[
            BulkOperation[User](
                method="POST",
                path="/Users",
                bulk_id="qwerty",
                data=User(user_name="Alice"),
            ),
            BulkOperation[Group](
                method="POST",
                path="/Groups",
                bulk_id="ytrewq",
                data=Group(
                    display_name="Tour Guides",
                    members=[GroupMember(type="User", value="bulkId:qwerty")],
                ),
            ),
        ]
    )

    response = sync_client.bulk(req)
    assert (
        response.operations[0].location
        == "https://example.com/v2/Users/92b725cd-9465-4e7d-8c16-01f8e146b87a"
    )
    assert (
        response.operations[1].location
        == "https://example.com/v2/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a"
    )


def test_bulk_request_payload(httpserver, sync_client):
    """Test that the operation payloads are sent in a bulk request context."""
    httpserver.expect_request(
        "/Bulk",
        method="POST",
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
            "Operations": [
                {
                    "method": "POST",
                    "bulkId": "qwerty",
                    "path": "/Users",
                    "data": {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                        "userName": "Alice",
                    },
                }
            ],
        },
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],
            "Operations": [],
        },
        status=200,
    )
    req = BulkRequest[User](
        operations=[
            BulkOperation[User](
                method="POST",
                path="/Users",
                bulk_id="qwerty",
                data=User(user_name="Alice"),
            )
        ]
    )

    assert isinstance(sync_client.bulk(req), BulkResponse)


def test_dont_check_response(httpserver, sync_client):
    """Test the check_response_payload attribute."""
    httpserver.expect_request("/Bulk", method="POST").respond_with_json(
        {"foo": "bar"}, status=200
    )
    req = BulkRequest[User](
        operations=[
            BulkOperation[User](
                method="POST",
                path="/Users",
                bulk_id="qwerty",
                data=User(user_name="Alice"),
            ),
        ]
    )

    response = sync_client.bulk(req, check_response_payload=False)
    assert response == {"foo": "bar"}


def test_dont_check_request_payload(httpserver, sync_client):
    """Test the check_request_payload attribute."""
    httpserver.expect_request(
        "/Bulk",
        method="POST",
        json={
            "operations": [
                {
                    "method": "POST",
                    "path": "/Users",
                    "data": {
                        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                        "userName": "Alice",
                    },
                },
            ],
        },
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],
            "Operations": [
                {
                    "location": "https://example.com/v2/Users/92b725cd-9465-4e7d-8c16-01f8e146b87a",
                    "method": "POST",
                    "bulkId": "qwerty",
                    "version": 'W/"4weymrEsh5O6cAEK"',
                    "status": "201",
                },
            ],
        },
        status=200,
    )
    req = {
        "operations": [
            {
                "method": "POST",
                "path": "/Users",
                "data": {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "userName": "Alice",
                },
            },
        ],
    }

    response = sync_client.bulk(req, check_request_payload=False)
    assert isinstance(response, BulkResponse)


@pytest.mark.parametrize("code", [400, 401, 403, 404, 409, 413, 500, 501])
def test_errors(httpserver, sync_client, code):
    """Test the error cases defined in RFC7644 §3.7.3."""
    httpserver.expect_request("/Bulk", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": str(code),
            "detail": f"{code} error",
        },
        status=code,
    )

    response = sync_client.bulk(raise_scim_errors=False)

    assert response == Error(
        schemas=["urn:ietf:params:scim:api:messages:2.0:Error"],
        status=code,
        detail=f"{code} error",
    )


def test_request_network_error(sync_client):
    """Test that httpx2 exceptions are transformed in RequestNetworkException."""
    with pytest.raises(
        RequestNetworkException, match="Network error happened during request"
    ):
        sync_client.bulk(url="http://invalid.test")


def test_no_operation(httpserver, sync_client):
    """Test a bulk response carrying no operation."""
    httpserver.expect_request("/Bulk", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],
            "Operations": [],
        },
        status=200,
    )
    req = BulkRequest[User](operations=[])

    response = sync_client.bulk(req)
    assert response.operations == []
