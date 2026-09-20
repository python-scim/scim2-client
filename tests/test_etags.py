"""Resource versioning, as defined in RFC7644 §3.14."""

import asyncio

import pytest
from scim2_models import ETag
from scim2_models import Meta
from scim2_models import ResponseParameters
from scim2_models import SCIMException
from scim2_models import ServiceProviderConfig
from scim2_models import User
from werkzeug.test import Client
from werkzeug.wrappers import Request
from werkzeug.wrappers import Response

from scim2_client.engines.httpx2 import AsyncClient
from scim2_client.engines.httpx2 import AsyncSCIMClient
from scim2_client.engines.werkzeug import TestSCIMClient
from scim2_client.errors import UnexpectedStatusCodeException

VERSION = 'W/"3694e05e9dff590"'


@pytest.fixture
def etag_client(sync_client):
    """Return a client bound to a server advertising ETag support."""
    sync_client.service_provider_config = ServiceProviderConfig(
        etag=ETag(supported=True)
    )
    return sync_client


@pytest.fixture
def versioned_user(user):
    """Return a user read with an ETag."""
    user.meta = Meta(version=VERSION)
    return user


def test_delete_sends_if_match(httpserver, etag_client, versioned_user):
    """Deleting a versioned resource is conditional on its version."""
    httpserver.expect_request(
        f"/Users/{versioned_user.id}",
        method="DELETE",
        headers={"If-Match": VERSION},
    ).respond_with_data(status=204, content_type="application/scim+json")

    assert etag_client.delete(versioned_user) is None


def test_modify_sends_if_match(httpserver, etag_client, versioned_user, patch_op):
    """Modifying a versioned resource is conditional on its version."""
    httpserver.expect_request(
        f"/Users/{versioned_user.id}",
        method="PATCH",
        headers={"If-Match": VERSION},
    ).respond_with_data(status=204, content_type="application/scim+json")

    assert etag_client.modify(versioned_user, patch_op) is None


def test_replace_sends_if_match(httpserver, etag_client, versioned_user):
    """Replacing a versioned resource is conditional on its version."""
    httpserver.expect_request(
        f"/Users/{versioned_user.id}",
        method="PUT",
        headers={"If-Match": VERSION},
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": versioned_user.id,
            "userName": versioned_user.user_name,
        },
        status=200,
    )

    assert etag_client.replace(versioned_user).id == versioned_user.id


def test_replace_sends_if_match_without_payload_check(
    httpserver, etag_client, versioned_user
):
    """The version of a raw payload is read too."""
    httpserver.expect_request(
        f"/Users/{versioned_user.id}",
        method="PUT",
        headers={"If-Match": VERSION},
    ).respond_with_json({}, status=200)

    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": versioned_user.id,
        "userName": versioned_user.user_name,
        "meta": {"version": VERSION},
    }
    response = etag_client.replace(
        payload,
        check_request_payload=False,
        check_response_payload=False,
        url=f"/Users/{versioned_user.id}",
    )
    assert response == {}


def test_no_if_match_without_etag_support(httpserver, sync_client, versioned_user):
    """No conditional header when the server does not advertise ETag support."""

    def handler(request):
        assert "If-Match" not in request.headers
        return Response(status=204, content_type="application/scim+json")

    httpserver.expect_request(
        f"/Users/{versioned_user.id}", method="DELETE"
    ).respond_with_handler(handler)

    assert sync_client.delete(versioned_user) is None


def test_no_if_match_without_version(httpserver, etag_client, user):
    """No conditional header when the resource was read without a version."""

    def handler(request):
        assert "If-Match" not in request.headers
        return Response(status=204, content_type="application/scim+json")

    httpserver.expect_request(
        f"/Users/{user.id}", method="DELETE"
    ).respond_with_handler(handler)

    assert etag_client.delete(user) is None


def test_no_if_match_without_a_resource_object(httpserver, etag_client, user):
    """No conditional header when the resource is designated by a type and an id."""

    def handler(request):
        assert "If-Match" not in request.headers
        return Response(status=204, content_type="application/scim+json")

    httpserver.expect_request(
        f"/Users/{user.id}", method="DELETE"
    ).respond_with_handler(handler)

    assert etag_client.delete(User, user.id) is None


def test_no_if_match_for_a_raw_payload_without_version(
    httpserver, etag_client, versioned_user
):
    """No conditional header when a raw payload carries no version."""

    def handler(request):
        assert "If-Match" not in request.headers
        return Response("{}", status=200, content_type="application/scim+json")

    httpserver.expect_request(
        f"/Users/{versioned_user.id}", method="PUT"
    ).respond_with_handler(handler)

    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": versioned_user.id,
        "userName": versioned_user.user_name,
    }
    etag_client.replace(
        payload,
        check_request_payload=False,
        check_response_payload=False,
        url=f"/Users/{versioned_user.id}",
    )


def test_user_provided_if_match_wins(httpserver, etag_client, versioned_user):
    """An explicit If-Match header is not overwritten."""
    httpserver.expect_request(
        f"/Users/{versioned_user.id}",
        method="DELETE",
        headers={"If-Match": 'W/"custom"'},
    ).respond_with_data(status=204, content_type="application/scim+json")

    response = etag_client.delete(versioned_user, headers={"If-Match": 'W/"custom"'})
    assert response is None


def test_version_is_read_from_the_etag_header(httpserver, etag_client, user):
    """The version is read from the ETag header when meta.version is empty."""
    httpserver.expect_request(f"/Users/{user.id}", method="GET").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": user.id,
            "userName": user.user_name,
        },
        status=200,
        headers={"ETag": VERSION},
    )

    response = etag_client.query(user.__class__, user.id)
    assert response.meta.version == VERSION


def test_meta_version_wins_over_the_etag_header(httpserver, etag_client, user):
    """The meta.version attribute is authoritative when the server sends both."""
    httpserver.expect_request(f"/Users/{user.id}", method="GET").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": user.id,
            "userName": user.user_name,
            "meta": {"resourceType": "User", "version": VERSION},
        },
        status=200,
        headers={"ETag": 'W/"stale"'},
    )

    response = etag_client.query(user.__class__, user.id)
    assert response.meta.version == VERSION


def test_list_responses_have_no_version(httpserver, etag_client):
    """The ETag header of a listing does not belong to any single resource."""
    httpserver.expect_request("/Users", method="GET").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 0,
            "Resources": [],
        },
        status=200,
        headers={"ETag": VERSION},
    )

    response = etag_client.query(User)
    assert response.total_results == 0


def test_precondition_failed(httpserver, etag_client, versioned_user):
    """A 412 tells the resource changed on the server since it was read."""
    httpserver.expect_request(
        f"/Users/{versioned_user.id}", method="DELETE"
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "412",
            "detail": "Failed to update. Resource has changed on the server.",
        },
        status=412,
    )

    with pytest.raises(SCIMException) as exc_info:
        etag_client.delete(versioned_user)

    assert exc_info.value.status == 412


def test_werkzeug_engine_sends_if_match(versioned_user):
    """The werkzeug engine forwards the conditional header to the application."""
    seen = {}

    @Request.application
    def app(request):
        seen["if_match"] = request.headers.get("If-Match")
        return Response(status=204, content_type="application/scim+json")

    client = TestSCIMClient(
        Client(app),
        resource_models=(User,),
        service_provider_config=ServiceProviderConfig(etag=ETag(supported=True)),
    )
    client.register_naive_resource_types()

    assert client.delete(versioned_user) is None
    assert seen["if_match"] == VERSION


def test_query_sends_if_none_match(httpserver, etag_client, versioned_user):
    """Reading a versioned resource again is conditional on it having changed."""
    httpserver.expect_request(
        f"/Users/{versioned_user.id}",
        method="GET",
        headers={"If-None-Match": VERSION},
    ).respond_with_data(status=304)

    assert etag_client.query(versioned_user) is versioned_user


def test_query_returns_the_fresh_resource_on_200(
    httpserver, etag_client, versioned_user
):
    """The server answers with the resource when it has changed."""
    httpserver.expect_request(
        f"/Users/{versioned_user.id}", method="GET"
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": versioned_user.id,
            "userName": versioned_user.user_name,
            "displayName": "Updated Name",
            "meta": {"resourceType": "User", "version": 'W/"newer"'},
        },
        status=200,
    )

    response = etag_client.query(versioned_user)
    assert response is not versioned_user
    assert response.display_name == "Updated Name"


def test_no_if_none_match_with_query_parameters(
    httpserver, etag_client, versioned_user
):
    """A partial representation cannot be replaced by the whole cached object."""

    def handler(request):
        assert "If-None-Match" not in request.headers
        return Response(
            '{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], '
            f'"id": "{versioned_user.id}", "userName": "bjensen@example.com"}}',
            status=200,
            content_type="application/scim+json",
        )

    httpserver.expect_request(
        f"/Users/{versioned_user.id}", method="GET"
    ).respond_with_handler(handler)

    response = etag_client.query(
        versioned_user, query_parameters=ResponseParameters(attributes=["userName"])
    )
    assert response.id == versioned_user.id


def test_no_if_none_match_without_a_resource_object(httpserver, etag_client, user):
    """No conditional header when the resource is designated by a type and an id."""

    def handler(request):
        assert "If-None-Match" not in request.headers
        return Response(
            '{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], '
            f'"id": "{user.id}", "userName": "bjensen@example.com"}}',
            status=200,
            content_type="application/scim+json",
        )

    httpserver.expect_request(f"/Users/{user.id}", method="GET").respond_with_handler(
        handler
    )

    assert etag_client.query(User, user.id).id == user.id


def test_not_modified_is_an_unexpected_status_code(
    httpserver, etag_client, versioned_user
):
    """A 304 is still checked against the expected status codes."""
    httpserver.expect_request(
        f"/Users/{versioned_user.id}", method="GET"
    ).respond_with_data(status=304)

    with pytest.raises(UnexpectedStatusCodeException):
        etag_client.query(versioned_user, expected_status_codes=[200])


def test_not_modified_without_payload_check(httpserver, etag_client, versioned_user):
    """A 304 carries no payload to return when responses are not validated."""
    httpserver.expect_request(
        f"/Users/{versioned_user.id}", method="GET"
    ).respond_with_data(status=304)

    assert etag_client.query(versioned_user, check_response_payload=False) is None


def test_unsolicited_not_modified(httpserver, etag_client):
    """A 304 the client did not ask for leaves it with nothing to return."""
    httpserver.expect_request("/Users", method="GET").respond_with_data(status=304)

    assert etag_client.query(User) is None


def test_werkzeug_engine_sends_if_none_match(versioned_user):
    """The werkzeug engine forwards the conditional header to the application."""
    seen = {}

    @Request.application
    def app(request):
        seen["if_none_match"] = request.headers.get("If-None-Match")
        return Response(status=304)

    client = TestSCIMClient(
        Client(app),
        resource_models=(User,),
        service_provider_config=ServiceProviderConfig(etag=ETag(supported=True)),
    )
    client.register_naive_resource_types()

    assert client.query(versioned_user) is versioned_user
    assert seen["if_none_match"] == VERSION


def test_async_engine_sends_if_none_match(httpserver, versioned_user):
    """The asynchronous engine handles conditional reads too."""
    httpserver.expect_request(
        f"/Users/{versioned_user.id}",
        method="GET",
        headers={"If-None-Match": VERSION},
    ).respond_with_data(status=304)

    async def query():
        async with AsyncClient(
            base_url=f"http://localhost:{httpserver.port}"
        ) as http_client:
            client = AsyncSCIMClient(
                http_client,
                resource_models=(User,),
                service_provider_config=ServiceProviderConfig(
                    etag=ETag(supported=True)
                ),
            )
            client.register_naive_resource_types()
            return await client.query(versioned_user)

    assert asyncio.run(query()) is versioned_user
