"""The reading a client makes of the payloads a nonconformant peer exchanges."""

import asyncio

import pytest
from scim2_models import ScimPolicy
from scim2_models import ScimProvider
from scim2_models import User

from scim2_client.engines.httpx2 import AsyncClient
from scim2_client.engines.httpx2 import AsyncSCIMClient
from scim2_client.errors import ResponsePayloadValidationException

USER_PAYLOAD = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "id": "2819c223-7f76-453a-919d-413861904646",
    "userName": "bjensen@example.com",
    "acmeDepartment": "Tour Operations",
}


@pytest.fixture
def httpserver(httpserver):
    """Serve a user carrying an attribute no schema declares."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646"
    ).respond_with_json(USER_PAYLOAD, status=200)
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PUT"
    ).respond_with_json(USER_PAYLOAD, status=200)
    httpserver.expect_request("/Users", method="POST").respond_with_json(
        USER_PAYLOAD, status=201
    )
    return httpserver


def tolerant_provider(unknown):
    return ScimProvider(models=[User], policy=ScimPolicy(unknown=unknown))


def test_unknown_attribute_in_a_response(sync_client):
    """A client describing no policy holds the server to the specification."""
    with pytest.raises(ResponsePayloadValidationException):
        sync_client.query(User, "2819c223-7f76-453a-919d-413861904646")


def test_tolerated_unknown_attribute_in_a_response(sync_client):
    """A policy ignoring the unknown attributes reads the rest of the payload."""
    sync_client.provider = tolerant_provider(ScimPolicy.Unknown.ignore)

    user = sync_client.query(User, "2819c223-7f76-453a-919d-413861904646")

    assert user.user_name == "bjensen@example.com"


def test_kept_unknown_attribute_is_carried_back(sync_client, httpserver):
    """An attribute the policy keeps is sent back to the server it came from."""
    sync_client.provider = tolerant_provider(ScimPolicy.Unknown.keep)
    user = sync_client.query(User, "2819c223-7f76-453a-919d-413861904646")

    sync_client.replace(user)

    assert httpserver.log[-1][0].json["acmeDepartment"] == "Tour Operations"


def test_unknown_attribute_in_a_request(sync_client):
    """A payload the client is handed is read under the policy as well."""
    sync_client.provider = tolerant_provider(ScimPolicy.Unknown.ignore)

    user = sync_client.create(USER_PAYLOAD)

    assert user.user_name == "bjensen@example.com"


def test_unknown_attribute_read_asynchronously(httpserver):
    """The policy rules the payloads the asynchronous engine exchanges."""

    async def query():
        async with AsyncClient(
            base_url=f"http://localhost:{httpserver.port}"
        ) as http_client:
            client = AsyncSCIMClient(
                http_client, provider=tolerant_provider(ScimPolicy.Unknown.ignore)
            )
            return await client.query(User, "2819c223-7f76-453a-919d-413861904646")

    assert asyncio.run(query()).user_name == "bjensen@example.com"
