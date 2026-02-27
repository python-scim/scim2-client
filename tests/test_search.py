import datetime

import pytest
from httpx import Client
from scim2_models import Error
from scim2_models import Group
from scim2_models import ListResponse
from scim2_models import Meta
from scim2_models import SearchRequest
from scim2_models import User

from scim2_client import RequestNetworkException
from scim2_client.engines.httpx import SyncSCIMClient


def test_all_objects(httpserver):
    """Test that a search request can be posted without SearchRequest arguments, and instantiate a ListResponse object."""
    httpserver.expect_request("/.search", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 2,
            "Resources": [
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
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "id": "074860c7-70e9-4db5-ad40-a32bab8be11d",
                    "userName": "jsmith@example.com",
                    "meta": {
                        "resourceType": "User",
                        "created": "2010-02-23T04:56:22Z",
                        "lastModified": "2011-06-13T04:42:34Z",
                        "version": 'W\\/"deadbeef0000"',
                        "location": "https://example.com/v2/Users/074860c7-70e9-4db5-ad40-a32bab8be11d",
                    },
                },
            ],
        },
        status=200,
    )

    client = Client(base_url=f"http://localhost:{httpserver.port}")
    scim_client = SyncSCIMClient(
        client,
        resource_models=(
            User,
            Group,
        ),
    )
    response = scim_client.search()
    assert response == ListResponse[User](
        total_results=2,
        resources=[
            User(
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
            ),
            User(
                id="074860c7-70e9-4db5-ad40-a32bab8be11d",
                user_name="jsmith@example.com",
                meta=Meta(
                    resource_type="User",
                    created=datetime.datetime(
                        2010, 2, 23, 4, 56, 22, tzinfo=datetime.timezone.utc
                    ),
                    last_modified=datetime.datetime(
                        2011, 6, 13, 4, 42, 34, tzinfo=datetime.timezone.utc
                    ),
                    version='W\\/"deadbeef0000"',
                    location="https://example.com/v2/Users/074860c7-70e9-4db5-ad40-a32bab8be11d",
                ),
            ),
        ],
    )


def test_search_request(httpserver):
    httpserver.expect_request("/.search", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "Resources": [
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
            ],
        },
        status=200,
    )
    req = SearchRequest(
        attributes=["userName", "displayName"],
        filter='userName Eq "john"',
        sort_by="userName",
        sort_order=SearchRequest.SortOrder.ascending,
        start_index=1,
        count=10,
    )

    client = Client(base_url=f"http://localhost:{httpserver.port}")
    scim_client = SyncSCIMClient(
        client,
        resource_models=(
            User,
            Group,
        ),
    )
    response = scim_client.search(req)
    user = response.resources[0]
    assert isinstance(user, User)
    assert user.id == "2819c223-7f76-453a-919d-413861904646"


def test_dont_check_response(httpserver):
    """Test the check_response_payload_attribute."""
    httpserver.expect_request("/.search", method="POST").respond_with_json(
        {"foo": "bar"}, status=200
    )

    req = SearchRequest(
        attributes=["userName", "displayName"],
        filter='userName Eq "john"',
        sort_by="userName",
        sort_order=SearchRequest.SortOrder.ascending,
        start_index=1,
        count=10,
    )

    client = Client(base_url=f"http://localhost:{httpserver.port}")
    scim_client = SyncSCIMClient(
        client,
        resource_models=(
            User,
            Group,
        ),
    )
    response = scim_client.search(req, check_response_payload=False)
    assert response == {"foo": "bar"}


def test_dont_check_request_payload(httpserver):
    """Test the check_request_payload attribute.

    TODO: Actually check that the payload is sent through the network
    """
    httpserver.expect_request("/.search", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "Resources": [
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
            ],
        },
        status=200,
    )
    req = {
        "attributes": ["userName", "displayName"],
        "filter": 'userName Eq "john"',
        "sort_by": "userName",
        "sort_order": SearchRequest.SortOrder.ascending.value,
        "start_index": 1,
        "count": 10,
    }

    client = Client(base_url=f"http://localhost:{httpserver.port}")
    scim_client = SyncSCIMClient(
        client,
        resource_models=(
            User,
            Group,
        ),
    )
    response = scim_client.search(req, check_request_payload=False)
    assert isinstance(response, ListResponse)


@pytest.mark.parametrize("code", [400, 401, 403, 404, 409, 413, 500, 501])
def test_errors(httpserver, code):
    """Test error cases defined in RFC7644."""
    httpserver.expect_request("/.search", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": str(code),
            "detail": f"{code} error",
        },
        status=code,
    )

    client = Client(base_url=f"http://localhost:{httpserver.port}")
    scim_client = SyncSCIMClient(
        client,
        resource_models=(
            User,
            Group,
        ),
    )
    response = scim_client.search(raise_scim_errors=False)

    assert response == Error(
        schemas=["urn:ietf:params:scim:api:messages:2.0:Error"],
        status=code,
        detail=f"{code} error",
    )


def test_request_network_error(httpserver):
    """Test that httpx exceptions are transformed in RequestNetworkException."""
    client = Client(base_url=f"http://localhost:{httpserver.port}")
    scim_client = SyncSCIMClient(client, resource_models=(User,))
    with pytest.raises(
        RequestNetworkException, match="Network error happened during request"
    ):
        scim_client.search(url="http://invalid.test")
