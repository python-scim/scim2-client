import json

import pytest
from httpx2 import Client
from httpx2 import ConnectError
from httpx2 import MockTransport
from httpx2 import Response
from scim2_models import Error
from scim2_models import InvalidValueException
from scim2_models import ResourceType
from scim2_models import SCIMException
from scim2_models import ScimProvider
from scim2_models import UniquenessException
from scim2_models import User

from scim2_client import RequestNetworkException
from scim2_client.engines.httpx2 import SyncSCIMClient


def make_client(handler):
    http_client = Client(
        base_url="https://scim.example.com", transport=MockTransport(handler)
    )
    provider = ScimProvider(
        models=[User], resource_types=[ResourceType.from_resource(User)]
    )
    return SyncSCIMClient(http_client, provider=provider)


def answering_error(error):
    """Build a client whose server answers every request with an error."""

    def handler(request):
        return Response(
            int(error.status or 400),
            content=json.dumps(error.model_dump()),
            headers={"Content-Type": "application/scim+json"},
        )

    return make_client(handler)


def test_server_error_uses_the_class_matching_the_scim_type():
    """A known scimType is raised as its dedicated exception."""
    error = Error(status=409, scim_type="uniqueness", detail="User already exists")

    with pytest.raises(UniquenessException) as exc_info:
        answering_error(error).query(User, "1")

    assert exc_info.value.to_error() == error


def test_server_error_keeps_unknown_status_and_scim_type():
    """A status and a scimType no exception class matches are kept."""
    error = Error(status=429, scim_type="tooManyRequests", detail="Slow down")

    with pytest.raises(SCIMException) as exc_info:
        answering_error(error).query(User, "1")

    assert exc_info.value.status == 429
    assert exc_info.value.scim_type == "tooManyRequests"
    assert exc_info.value.to_error() == error


def test_server_error_carries_the_response():
    """The response that carried a server error is readable on the exception."""
    error = Error(status=404, detail="Not found")

    with pytest.raises(SCIMException) as exc_info:
        answering_error(error).query(User, "1")

    assert exc_info.value.response.status_code == 404


def test_refused_request_has_no_response():
    """A request the client refuses before sending it has no response."""
    client = answering_error(Error(status=500))
    payload = {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Invalid"]}

    with pytest.raises(InvalidValueException) as exc_info:
        client.create(payload)

    assert exc_info.value.response is None


def test_server_error_without_status_keeps_the_default_one():
    """An error object carrying no status is raised with the default status."""
    error = Error(detail="Something happened")

    with pytest.raises(SCIMException) as exc_info:
        answering_error(error).query(User, "1")

    assert exc_info.value.status == 400
    assert exc_info.value.to_error() == error


def test_network_error_has_the_request_payload_and_no_response():
    """A request that cannot reach the server keeps its payload and has no response."""

    def handler(request):
        raise ConnectError("unreachable", request=request)

    with pytest.raises(RequestNetworkException) as exc_info:
        make_client(handler).create(User(user_name="bob"))

    assert exc_info.value.source["userName"] == "bob"
    assert exc_info.value.response is None
