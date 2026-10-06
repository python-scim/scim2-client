import asyncio
import json

import pytest
from scim2_models import BulkOperation
from scim2_models import BulkRequest
from scim2_models import PatchOp
from scim2_models import PatchOperation
from scim2_models import ScimProvider
from scim2_models import SearchRequest
from scim2_models import User

from scim2_client.engines.asgi import ASGISCIMClient

scim2_server = pytest.importorskip("scim2_server")
from scim2_server.applications.asgi import ASGIApplication  # noqa: E402
from scim2_server.memory import AsyncInMemoryStorage  # noqa: E402
from scim2_server.utils import load_default_provider  # noqa: E402


def respond(status=200, body=b"", headers=()):
    """Return the messages of a response sent in one piece."""
    return [
        {"type": "http.response.start", "status": status, "headers": list(headers)},
        {"type": "http.response.body", "body": body},
    ]


async def echo(scope, receive, send):
    """Answer the scope of the request, and its body."""
    message = await receive()
    seen = {
        key: value
        for key, value in scope.items()
        if key not in ("headers", "raw_path", "query_string")
    }
    seen["raw_path"] = scope["raw_path"].decode()
    seen["query_string"] = scope["query_string"].decode()
    seen["headers"] = [
        [name.decode(), value.decode()] for name, value in scope["headers"]
    ]
    seen["body"] = message["body"].decode()
    for message in respond(body=json.dumps(seen).encode()):
        await send(message)


@pytest.fixture
async def scim_client():
    app = ASGIApplication(AsyncInMemoryStorage(), load_default_provider())
    scim_client = ASGISCIMClient(app, base_url="http://localhost/v2")
    await scim_client.discover()
    return scim_client


async def test_operations_reach_the_application(scim_client):
    """Every SCIM operation is served by the application."""
    User = scim_client.get_resource_model("User")

    user = await scim_client.create(User(user_name="bjensen", display_name="Babs"))
    assert user.meta.location == f"http://localhost/v2/Users/{user.id}"
    assert (await scim_client.query(User, user.id)).display_name == "Babs"

    found = await scim_client.search(
        User,
        SearchRequest(filter='userName eq "bjensen"', attributes=["userName"]),
    )
    assert [resource.id for resource in found.resources] == [user.id]

    replaced = await scim_client.replace(
        User(id=user.id, user_name="bjensen", display_name="Barbara")
    )
    assert replaced.display_name == "Barbara"

    patch_op = PatchOp[User](
        operations=[
            PatchOperation(
                op=PatchOperation.Op.replace_, path="displayName", value="Bab"
            )
        ]
    )
    await scim_client.modify(User, user.id, patch_op)
    assert (await scim_client.query(User, user.id)).display_name == "Bab"

    await scim_client.delete(User, user.id)
    assert (await scim_client.query(User)).total_results == 0


async def test_bulk_requests_reach_the_application(scim_client):
    """A bulk request is posted to the application."""
    User = scim_client.get_resource_model("User")
    request = BulkRequest[User](
        operations=[
            BulkOperation[User](
                method=BulkOperation.Method.post,
                path="/Users",
                bulk_id="qwerty",
                data=User(user_name="bjensen"),
            )
        ]
    )

    response = await scim_client.bulk(request)

    assert response.operations[0].status == 201


async def test_raw_request_returns_the_response_of_the_application(scim_client):
    """A raw request returns the status, headers and body of the application."""
    response = await scim_client.request("DELETE", "/Schemas")

    assert response.status_code == 405
    assert response.headers.get("allow") == "GET"
    assert response.json()["status"] == "405"


async def test_scope_describes_the_request():
    """The scope has the method, path, query and headers of the request, and the body follows."""
    client = ASGISCIMClient(echo, base_url="https://scim.test/scim/v2")

    response = await client.request(
        "POST",
        "/Users/%C3%A9t%C3%A9",
        params={"attributes": "userName"},
        json={"userName": "bjensen"},
        headers={"X-Test": "foo"},
    )
    seen = response.json()

    assert seen["type"] == "http"
    assert seen["asgi"] == {"version": "3.0"}
    assert seen["method"] == "POST"
    assert seen["scheme"] == "https"
    assert seen["path"] == "/scim/v2/Users/été"
    assert seen["raw_path"] == "/scim/v2/Users/%C3%A9t%C3%A9"
    assert seen["query_string"] == "attributes=userName"
    assert seen["root_path"] == ""
    assert seen["server"] == ["scim.test", 443]
    assert seen["headers"] == [
        ["host", "scim.test"],
        ["content-type", "application/json"],
        ["content-length", "23"],
        ["x-test", "foo"],
    ]
    assert seen["body"] == '{"userName": "bjensen"}'


async def test_explicit_port_is_the_server_port():
    """The port of the base URL is the port of the server."""
    client = ASGISCIMClient(echo, base_url="http://scim.test:8080")

    seen = (await client.request("GET", "/Users")).json()

    assert seen["server"] == ["scim.test", 8080]
    assert seen["body"] == ""


async def test_scope_keys_are_added_to_every_request():
    """The scope of the client is added to the scope of every request."""
    client = ASGISCIMClient(echo, scope={"user": "admin"})

    assert (await client.request("GET", "/Users")).json()["user"] == "admin"


async def test_default_headers_are_sent_with_scim_operations():
    """The default headers reach the application with every SCIM operation."""
    seen = {}

    async def app(scope, receive, send):
        seen["headers"] = dict(scope["headers"])
        for message in respond(status=204):
            await send(message)

    client = ASGISCIMClient(
        app,
        headers={"Authorization": "Bearer token"},
        provider=ScimProvider(models=[User]),
    )
    await client.delete(User, "1")

    assert seen["headers"][b"authorization"] == b"Bearer token"


async def test_body_sent_in_several_parts_is_joined():
    """The parts of a body are joined, and the response headers are read."""

    async def app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/scim+json")],
            }
        )
        await send({"type": "http.response.body", "body": b"foo", "more_body": True})
        await send({"type": "http.response.body", "more_body": True})
        await send({"type": "http.response.body", "body": b"bar"})

    response = await ASGISCIMClient(app).request("GET", "/Users")

    assert response.content == b"foobar"
    assert response.headers.get("Content-Type") == "application/scim+json"


async def test_disconnection_is_received_once_the_response_is_sent():
    """An application listening for the disconnection is not interrupted before its response is sent."""
    events = []

    async def app(scope, receive, send):
        await receive()

        async def listen_for_disconnect():
            message = await receive()
            events.append(message["type"])

        listener = asyncio.create_task(listen_for_disconnect())
        await send({"type": "http.response.start", "status": 200})
        await asyncio.sleep(0)
        events.append("body")
        await send({"type": "http.response.body", "body": b"foo"})
        await listener

    response = await ASGISCIMClient(app).request("GET", "/Users")

    assert response.content == b"foo"
    assert events == ["body", "http.disconnect"]


async def test_exception_of_the_application_reaches_the_caller():
    """An exception raised by the application is not turned into a response."""

    async def app(scope, receive, send):
        raise ZeroDivisionError()

    with pytest.raises(ZeroDivisionError):
        await ASGISCIMClient(app).request("GET", "/Users")


async def test_application_returning_without_response_is_refused():
    """An application that returns before its response is sent does not follow ASGI."""

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200})
        await send({"type": "http.response.body", "body": b"foo", "more_body": True})

    with pytest.raises(RuntimeError, match="returned before sending its response"):
        await ASGISCIMClient(app).request("GET", "/Users")


async def test_body_before_the_response_start_is_refused():
    """An application cannot send a body before the status of the response."""

    async def app(scope, receive, send):
        await send({"type": "http.response.body", "body": b"foo"})

    with pytest.raises(RuntimeError, match="body before starting the response"):
        await ASGISCIMClient(app).request("GET", "/Users")
