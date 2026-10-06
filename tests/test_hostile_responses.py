import asyncio
import gc
import json

import pytest
from httpx2 import MockTransport
from httpx2 import Response
from scim2_models import ListResponse
from scim2_models import ResourceType
from scim2_models import SCIMException
from scim2_models import ScimProvider
from scim2_models import User

from scim2_client import InvalidServiceDescriptionException
from scim2_client import ResponsePayloadValidationException
from scim2_client import SCIMResponseException
from scim2_client import UnexpectedContentFormatException
from scim2_client.engines.httpx2 import AsyncClient
from scim2_client.engines.httpx2 import AsyncSCIMClient
from scim2_client.engines.httpx2 import Client
from scim2_client.engines.httpx2 import SyncSCIMClient
from scim2_client.engines.wsgi import WSGISCIMClient

BASE_URL = "https://scim.example.com/scim/v2"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"

UNDECODABLE_BODIES = [
    pytest.param(b"1" + b"0" * 5_000, id="integer-too-long"),
    pytest.param(b'{"userName": "\xff"}', id="invalid-utf8"),
    pytest.param(b"{", id="truncated"),
]

DEEPLY_NESTED_BODIES = [
    pytest.param(b"[" * 100_000 + b"]" * 100_000, id="array"),
    pytest.param(b'{"a":' * 100_000 + b"1" + b"}" * 100_000, id="object"),
]

NOT_OBJECT_BODIES = [
    pytest.param(b"[1, 2]", id="array"),
    pytest.param(b'"hello"', id="string"),
    pytest.param(b"1", id="number"),
    pytest.param(b"true", id="boolean"),
]

INVALID_SCHEMAS_BODIES = [
    pytest.param(b'{"schemas": 1}', id="number"),
    pytest.param(b'{"schemas": NaN}', id="nan"),
    pytest.param(b'{"schemas": null}', id="null"),
    pytest.param(b'{"schemas": {"a": 1}}', id="object"),
    pytest.param(
        b'{"schemas": "urn:ietf:params:scim:schemas:core:2.0:User"}', id="string"
    ),
    pytest.param(b'{"schemas": [1]}', id="list-of-numbers"),
]

INVALID_ERROR_BODIES = [
    pytest.param(
        {"schemas": [ERROR_SCHEMA], "status": "abc"}, id="status-not-a-number"
    ),
    pytest.param({"schemas": [ERROR_SCHEMA], "status": [400]}, id="status-list"),
    pytest.param(
        {"schemas": [ERROR_SCHEMA], "status": "400", "scimType": {"a": 1}},
        id="scim-type-object",
    ),
]


def discover(client):
    """Discover the server with a client that knows nothing of it yet."""
    app = client.client if isinstance(client, SyncSCIMClient) else client.app
    return type(client)(app, provider=ScimProvider()).discover()


CALLS = [
    pytest.param(lambda client: client.query(User, "1"), id="query"),
    pytest.param(lambda client: client.query(User), id="search"),
    pytest.param(lambda client: client.create(User(user_name="bob")), id="create"),
    pytest.param(
        lambda client: client.replace(User(id="1", user_name="bob")), id="replace"
    ),
    pytest.param(lambda client: client.delete(User, "1"), id="delete"),
    pytest.param(discover, id="discover"),
]


def provider():
    return ScimProvider(
        models=[User], resource_types=[ResourceType.from_resource(User)]
    )


def answering(body, status=200):
    def handler(request):
        return Response(
            status, content=body, headers={"Content-Type": "application/scim+json"}
        )

    return MockTransport(handler)


def httpx2_client(body, status=200, **kwargs):
    http_client = Client(base_url=BASE_URL, transport=answering(body, status))
    return SyncSCIMClient(http_client, **{"provider": provider(), **kwargs})


def wsgi_client(body, status=200, **kwargs):
    def app(environ, start_response):
        start_response(f"{status} -", [("Content-Type", "application/scim+json")])
        return [body.encode() if isinstance(body, str) else body]

    return WSGISCIMClient(app, **{"provider": provider(), **kwargs})


@pytest.mark.parametrize("body", UNDECODABLE_BODIES)
@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize("make_client", [httpx2_client, wsgi_client])
def test_undecodable_body_is_an_unexpected_content_format(make_client, call, body):
    """A body the JSON decoder chokes on is reported as a body that is not JSON."""
    with pytest.raises(UnexpectedContentFormatException):
        call(make_client(body))


@pytest.mark.parametrize("body", DEEPLY_NESTED_BODIES)
@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize("make_client", [httpx2_client, wsgi_client])
def test_deeply_nested_body_is_a_response_error(make_client, call, body):
    """A body nested very deep is reported as a SCIM response error.

    Whether the JSON decoder goes that deep depends on the Python version and on
    the stack size of the machine, so the exact error depends on them too.
    """
    with pytest.raises(SCIMResponseException):
        call(make_client(body))


@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize("make_client", [httpx2_client, wsgi_client])
def test_decoder_recursion_error_is_an_unexpected_content_format(
    make_client, call, monkeypatch
):
    """A body the JSON decoder cannot go deep enough into is reported as a body that is not JSON."""

    def exceed_the_recursion_limit(*args, **kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(json, "loads", exceed_the_recursion_limit)

    with pytest.raises(UnexpectedContentFormatException):
        call(make_client(b"{}"))


@pytest.mark.parametrize("body", NOT_OBJECT_BODIES)
@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize("make_client", [httpx2_client, wsgi_client])
def test_body_that_is_not_an_object_is_refused(make_client, call, body):
    """A SCIM message is a JSON object, whatever JSON value the server sends."""
    with pytest.raises(UnexpectedContentFormatException, match="is not a JSON object"):
        call(make_client(body))


@pytest.mark.parametrize("status", [400, 404, 500])
@pytest.mark.parametrize("body", NOT_OBJECT_BODIES)
def test_error_status_with_a_body_that_is_not_an_object_is_refused(body, status):
    """An error response is read as a SCIM message too."""
    client = httpx2_client(body, status)

    with pytest.raises(UnexpectedContentFormatException, match="is not a JSON object"):
        client.query(User, "1")


@pytest.mark.parametrize("body", INVALID_SCHEMAS_BODIES)
@pytest.mark.parametrize("call", CALLS)
@pytest.mark.parametrize("make_client", [httpx2_client, wsgi_client])
def test_schemas_that_are_not_a_list_of_strings_are_refused(make_client, call, body):
    """The schemas select the model of the payload, so they must be URIs."""
    with pytest.raises(
        UnexpectedContentFormatException, match="are not a list of strings"
    ):
        call(make_client(body))


@pytest.mark.parametrize("body", NOT_OBJECT_BODIES + INVALID_SCHEMAS_BODIES)
def test_unchecked_response_is_returned_as_sent(body):
    """Without response checks, the decoded payload is handed over untouched."""
    client = httpx2_client(body, check_response_payload=False)

    assert client.query(User, "1") == json.loads(body)


@pytest.mark.parametrize("payload", INVALID_ERROR_BODIES)
@pytest.mark.parametrize("raise_scim_errors", [True, False])
def test_invalid_error_object_is_a_validation_failure(payload, raise_scim_errors):
    """An Error object that does not validate is reported as an invalid payload."""
    client = httpx2_client(
        json.dumps(payload).encode(), 400, raise_scim_errors=raise_scim_errors
    )

    with pytest.raises(ResponsePayloadValidationException) as exc_info:
        client.query(User, "1")

    assert any("Error" in note for note in exc_info.value.__notes__)


@pytest.mark.parametrize("body", NOT_OBJECT_BODIES)
async def test_async_client_refuses_a_body_that_is_not_an_object(body):
    """The asynchronous client reads the responses as the synchronous one."""
    http_client = AsyncClient(base_url=BASE_URL, transport=answering(body))
    client = AsyncSCIMClient(http_client, provider=provider())

    with pytest.raises(UnexpectedContentFormatException, match="is not a JSON object"):
        await client.query(User, "1")


@pytest.mark.parametrize("body", UNDECODABLE_BODIES)
async def test_async_client_refuses_an_undecodable_body(body):
    """The asynchronous client decodes the responses as the synchronous one."""
    http_client = AsyncClient(base_url=BASE_URL, transport=answering(body))
    client = AsyncSCIMClient(http_client, provider=provider())

    with pytest.raises(UnexpectedContentFormatException):
        await client.query(User, "1")


@pytest.mark.parametrize("body", DEEPLY_NESTED_BODIES)
async def test_async_client_refuses_a_deeply_nested_body(body):
    """The asynchronous client reports a body nested very deep as the synchronous one."""
    http_client = AsyncClient(base_url=BASE_URL, transport=answering(body))
    client = AsyncSCIMClient(http_client, provider=provider())

    with pytest.raises(SCIMResponseException):
        await client.query(User, "1")


FORBIDDEN = json.dumps(
    {"schemas": [ERROR_SCHEMA], "status": "403", "detail": "Forbidden"}
).encode()
EMPTY_LIST = (
    ListResponse[ResourceType](total_results=0, resources=[])
    .model_dump_json(by_alias=True)
    .encode()
)


def async_discovering_client(body, status=200, **kwargs):
    http_client = AsyncClient(base_url=BASE_URL, transport=answering(body, status))
    return AsyncSCIMClient(http_client, provider=ScimProvider(), **kwargs)


async def discover(client):
    if isinstance(client, AsyncSCIMClient):
        return await client.discover()

    return client.discover()


def sync_discovering_client(body, status=200, **kwargs):
    return httpx2_client(body, status, provider=ScimProvider(), **kwargs)


DISCOVERING_CLIENTS = [sync_discovering_client, async_discovering_client]


@pytest.mark.parametrize("make_client", DISCOVERING_CLIENTS)
async def test_discovery_raises_the_errors_the_server_returns(make_client):
    """Discovery cannot describe the server from an Error object, even when the client returns them."""
    client = make_client(FORBIDDEN, 403, raise_scim_errors=False)

    with pytest.raises(SCIMException, match="Forbidden"):
        await discover(client)


@pytest.mark.parametrize("make_client", DISCOVERING_CLIENTS)
async def test_discovery_validates_the_payloads(make_client):
    """Discovery builds the models from the published objects, even when the client returns raw payloads."""
    client = make_client(EMPTY_LIST, check_response_payload=False)

    with pytest.raises(SCIMResponseException, match="ServiceProviderConfig"):
        await discover(client)


@pytest.mark.parametrize("make_client", DISCOVERING_CLIENTS)
async def test_discovery_refuses_an_empty_response(make_client):
    """A discovery endpoint answering without content describes nothing."""
    client = make_client(b"")

    with pytest.raises(InvalidServiceDescriptionException, match="returned no content"):
        await discover(client)


async def test_async_discovery_retrieves_every_failure():
    """Every failing discovery query is awaited, and the first one in order is raised."""

    def handler(request):
        payload = {
            "schemas": [ERROR_SCHEMA],
            "status": "403",
            "detail": request.url.path,
        }
        return Response(
            403, json=payload, headers={"Content-Type": "application/scim+json"}
        )

    unretrieved = []
    asyncio.get_running_loop().set_exception_handler(
        lambda loop, context: unretrieved.append(context)
    )
    http_client = AsyncClient(base_url=BASE_URL, transport=MockTransport(handler))
    client = AsyncSCIMClient(http_client, provider=ScimProvider())

    with pytest.raises(SCIMException, match="/scim/v2/ResourceTypes"):
        await client.discover()

    # Let the other queries finish, then collect them as their frames are dropped.
    await asyncio.sleep(0.01)
    gc.collect()
    assert unretrieved == []
