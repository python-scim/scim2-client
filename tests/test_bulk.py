"""Bulk operations, as defined in RFC7644 §3.7."""

import asyncio
import json

import pytest
from scim2_models import Bulk
from scim2_models import BulkOperation
from scim2_models import BulkRequest
from scim2_models import BulkResponse
from scim2_models import Error
from scim2_models import Group
from scim2_models import GroupMember
from scim2_models import InvalidValueException
from scim2_models import ServiceProviderConfig
from scim2_models import User
from werkzeug.test import Client
from werkzeug.wrappers import Request
from werkzeug.wrappers import Response

from scim2_client import RequestNetworkException
from scim2_client.engines.httpx2 import AsyncClient
from scim2_client.engines.httpx2 import AsyncSCIMClient
from scim2_client.engines.werkzeug import TestSCIMClient

USER_OPERATION = BulkOperation[User](
    method="POST",
    path="/Users",
    bulk_id="qwerty",
    data=User(user_name="Alice"),
)
GROUP_OPERATION = BulkOperation[Group](
    method="POST",
    path="/Groups",
    bulk_id="ytrewq",
    data=Group(
        display_name="Tour Guides",
        members=[GroupMember(type="User", value="bulkId:qwerty")],
    ),
)


@pytest.fixture
def bulk_client(sync_client):
    """Return a client bound to a server advertising its bulk capabilities."""
    sync_client.service_provider_config = ServiceProviderConfig(
        bulk=Bulk(supported=True, max_operations=1000, max_payload_size=1048576)
    )
    return sync_client


RESPONSE_PAYLOAD = {
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
}


@pytest.fixture
def bulk_response(httpserver):
    """Make the server answer a successful bulk response."""

    def register(**kwargs):
        httpserver.expect_request("/Bulk", method="POST", **kwargs).respond_with_json(
            RESPONSE_PAYLOAD, status=200
        )

    return register


def test_bulk_request(bulk_response, sync_client):
    """Test that a bulk request is posted and its response is validated."""
    bulk_response()
    req = BulkRequest[User | Group](operations=[USER_OPERATION, GROUP_OPERATION])

    response = sync_client.bulk(req)

    assert (
        response.operations[0].location
        == "https://example.com/v2/Users/92b725cd-9465-4e7d-8c16-01f8e146b87a"
    )
    assert (
        response.operations[1].location
        == "https://example.com/v2/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a"
    )


def test_bulk_request_payload(bulk_response, sync_client):
    """Test that the operation payloads are sent in a bulk request context."""
    bulk_response(
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
        }
    )
    req = BulkRequest[User](operations=[USER_OPERATION])

    assert isinstance(sync_client.bulk(req), BulkResponse)


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


def test_missing_bulk_request(sync_client):
    """Test that a bulk request without operations is refused."""
    with pytest.raises(InvalidValueException, match=r"Missing bulk operations"):
        sync_client.bulk()


def test_dont_check_request_payload(bulk_response, sync_client):
    """Test the check_request_payload attribute."""
    bulk_response(json={"operations": [{"method": "POST", "path": "/Users"}]})

    response = sync_client.bulk(
        {"operations": [{"method": "POST", "path": "/Users"}]},
        check_request_payload=False,
    )

    assert isinstance(response, BulkResponse)


def test_dont_check_response(httpserver, sync_client):
    """Test the check_response_payload attribute."""
    httpserver.expect_request("/Bulk", method="POST").respond_with_json(
        {"foo": "bar"}, status=200
    )
    req = BulkRequest[User](operations=[USER_OPERATION])

    response = sync_client.bulk(req, check_response_payload=False)

    assert response == {"foo": "bar"}


@pytest.mark.parametrize("code", [400, 401, 403, 404, 409, 413, 500, 501])
def test_errors(httpserver, sync_client, code):
    """Test the error cases defined in RFC7644 §3.12."""
    httpserver.expect_request("/Bulk", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": str(code),
            "detail": f"{code} error",
        },
        status=code,
    )
    req = BulkRequest[User](operations=[USER_OPERATION])

    response = sync_client.bulk(req, raise_scim_errors=False)

    assert response == Error(
        schemas=["urn:ietf:params:scim:api:messages:2.0:Error"],
        status=code,
        detail=f"{code} error",
    )


def test_request_network_error(sync_client):
    """Test that httpx2 exceptions are transformed in RequestNetworkException."""
    req = BulkRequest[User](operations=[USER_OPERATION])

    with pytest.raises(
        RequestNetworkException, match="Network error happened during request"
    ):
        sync_client.bulk(req, url="http://invalid.test")


def test_advertised_capabilities(bulk_response, bulk_client):
    """Test that a request within the advertised capabilities is sent."""
    bulk_response()
    req = BulkRequest[User | Group](operations=[USER_OPERATION, GROUP_OPERATION])

    assert isinstance(bulk_client.bulk(req), BulkResponse)


def test_advertised_capabilities_without_limits(bulk_response, bulk_client):
    """Test a server advertising bulk support without any limit."""
    bulk_response()
    bulk_client.service_provider_config.bulk = Bulk(supported=True)
    req = BulkRequest[User](operations=[USER_OPERATION])

    assert isinstance(bulk_client.bulk(req), BulkResponse)


def test_unsupported_by_the_server(bulk_client):
    """Test that bulk requests are not sent to a server that does not serve them."""
    bulk_client.service_provider_config.bulk = Bulk(supported=False)
    req = BulkRequest[User](operations=[USER_OPERATION])

    with pytest.raises(
        InvalidValueException, match=r"The server does not support bulk requests"
    ):
        bulk_client.bulk(req)


def test_too_many_operations(bulk_client):
    """Test that requests exceeding the advertised maxOperations are not sent."""
    bulk_client.service_provider_config.bulk.max_operations = 1
    req = BulkRequest[User | Group](operations=[USER_OPERATION, GROUP_OPERATION])

    with pytest.raises(
        InvalidValueException, match=r"limited to 1 operations by the server"
    ):
        bulk_client.bulk(req)


def test_payload_too_large(bulk_client):
    """Test that requests exceeding the advertised maxPayloadSize are not sent."""
    bulk_client.service_provider_config.bulk.max_payload_size = 10
    req = BulkRequest[User](operations=[USER_OPERATION])

    with pytest.raises(
        InvalidValueException, match=r"limited to 10 bytes by the server"
    ):
        bulk_client.bulk(req)


def test_async_engine(httpserver):
    """Test that the asynchronous engine posts bulk requests."""
    httpserver.expect_request("/Bulk", method="POST").respond_with_json(
        RESPONSE_PAYLOAD, status=200
    )

    async def bulk():
        async with AsyncClient(
            base_url=f"http://localhost:{httpserver.port}"
        ) as http_client:
            client = AsyncSCIMClient(http_client, resource_models=(User, Group))
            client.register_naive_resource_types()
            return await client.bulk(BulkRequest[User](operations=[USER_OPERATION]))

    assert isinstance(asyncio.run(bulk()), BulkResponse)


def test_werkzeug_engine():
    """Test that the werkzeug engine posts bulk requests."""
    seen = {}

    @Request.application
    def app(request):
        seen["payload"] = request.get_json()
        return Response(
            json.dumps(RESPONSE_PAYLOAD),
            status=200,
            content_type="application/scim+json",
        )

    client = TestSCIMClient(Client(app), resource_models=(User, Group))
    client.register_naive_resource_types()

    assert isinstance(
        client.bulk(BulkRequest[User](operations=[USER_OPERATION])), BulkResponse
    )
    assert seen["payload"]["Operations"][0]["bulkId"] == "qwerty"
