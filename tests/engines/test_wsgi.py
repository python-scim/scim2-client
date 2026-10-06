import json
import sys

import pytest
from scim2_models import BulkOperation
from scim2_models import BulkRequest
from scim2_models import Group
from scim2_models import PatchOp
from scim2_models import PatchOperation
from scim2_models import ResourceType
from scim2_models import ScimProvider
from scim2_models import SearchRequest
from scim2_models import User

from scim2_client.engines.wsgi import WSGISCIMClient

scim2_server = pytest.importorskip("scim2_server")
from scim2_server.applications.wsgi import WSGIApplication  # noqa: E402
from scim2_server.memory import InMemoryStorage  # noqa: E402
from scim2_server.utils import load_default_provider  # noqa: E402


def echo(environ, start_response):
    """Answer the WSGI environment of the request, and its body."""
    body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0))
    seen = {
        key: value for key, value in environ.items() if isinstance(value, str | tuple)
    }
    seen["body"] = body.decode()
    start_response("200 OK", [("Content-Type", "application/json")])
    return [json.dumps(seen).encode()]


@pytest.fixture
def scim_client():
    app = WSGIApplication(InMemoryStorage(), load_default_provider())
    scim_client = WSGISCIMClient(app, base_url="http://localhost/v2")
    scim_client.discover()
    return scim_client


def test_operations_reach_the_application(scim_client):
    """Every SCIM operation is served by the application."""
    User = scim_client.get_resource_model("User")

    user = scim_client.create(User(user_name="bjensen", display_name="Babs"))
    assert user.meta.location == f"http://localhost/v2/Users/{user.id}"
    assert scim_client.query(User, user.id).display_name == "Babs"

    found = scim_client.search(
        User,
        SearchRequest(filter='userName eq "bjensen"', attributes=["userName"]),
    )
    assert [resource.id for resource in found.resources] == [user.id]

    replaced = scim_client.replace(
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
    scim_client.modify(User, user.id, patch_op)
    assert scim_client.query(User, user.id).display_name == "Bab"

    scim_client.delete(User, user.id)
    assert scim_client.query(User).total_results == 0


def test_bulk_requests_reach_the_application(scim_client):
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

    response = scim_client.bulk(request)

    assert response.operations[0].status == 201


def test_raw_request_returns_the_response_of_the_application(scim_client):
    """A raw request returns the status, headers and body of the application."""
    response = scim_client.request("DELETE", "/Schemas")

    assert response.status_code == 405
    assert response.headers.get("allow") == "GET"
    assert response.json()["status"] == "405"


def test_raw_request_sends_a_raw_body(scim_client):
    """A raw body reaches the application as it is."""
    response = scim_client.request(
        "POST",
        "/Users",
        content=b"not json",
        headers={"Content-Type": "application/scim+json"},
    )

    assert response.status_code == 400


def test_environ_describes_the_request():
    """The WSGI environment has the method, path, query, headers and body of the request."""
    client = WSGISCIMClient(echo, base_url="https://scim.test/scim/v2")

    seen = client.request(
        "POST",
        "/Users/%C3%A9t%C3%A9",
        params={"attributes": "userName"},
        json={"userName": "bjensen"},
        headers={"X-Test": "foo"},
    ).json()

    assert seen["REQUEST_METHOD"] == "POST"
    assert seen["SCRIPT_NAME"] == ""
    assert seen["PATH_INFO"] == "/scim/v2/Users/été".encode().decode("latin-1")
    assert seen["QUERY_STRING"] == "attributes=userName"
    assert seen["SERVER_NAME"] == "scim.test"
    assert seen["SERVER_PORT"] == "443"
    assert seen["wsgi.url_scheme"] == "https"
    assert seen["HTTP_HOST"] == "scim.test"
    assert seen["HTTP_X_TEST"] == "foo"
    assert seen["CONTENT_TYPE"] == "application/json"
    assert seen["CONTENT_LENGTH"] == "23"
    assert "HTTP_CONTENT_TYPE" not in seen
    assert seen["body"] == '{"userName": "bjensen"}'


def test_explicit_port_is_the_server_port():
    """The port of the base URL is the port of the server."""
    client = WSGISCIMClient(echo, base_url="http://scim.test:8080")

    seen = client.request("GET", "/Users").json()

    assert seen["SERVER_PORT"] == "8080"
    assert seen["HTTP_HOST"] == "scim.test:8080"
    assert "CONTENT_LENGTH" not in seen


def test_repeated_headers_are_joined():
    """Repeated headers are joined with commas (RFC 9110 §5.3)."""
    client = WSGISCIMClient(echo, headers=[("X-Test", "foo")])

    seen = client.request(
        "GET", "/Users", headers=[("X-Other", "bar"), ("X-Other", "baz")]
    ).json()

    assert seen["HTTP_X_TEST"] == "foo"
    assert seen["HTTP_X_OTHER"] == "bar, baz"


def test_environ_keys_are_added_to_every_request():
    """The environ of the client is added to the environment of every request."""
    client = WSGISCIMClient(echo, environ={"REMOTE_USER": "admin"})

    assert client.request("GET", "/Users").json()["REMOTE_USER"] == "admin"


def test_default_headers_are_sent_with_scim_operations():
    """The default headers reach the application with every SCIM operation."""
    seen = {}

    def app(environ, start_response):
        seen["authorization"] = environ.get("HTTP_AUTHORIZATION")
        start_response("204 No Content", [])
        return []

    client = WSGISCIMClient(
        app,
        headers={"Authorization": "Bearer token"},
        provider=ScimProvider(models=[User]),
    )
    client.delete(User, "1")

    assert seen["authorization"] == "Bearer token"


def test_exception_of_the_application_reaches_the_caller():
    """An exception raised by the application is not turned into a response."""

    def app(environ, start_response):
        raise ZeroDivisionError()

    client = WSGISCIMClient(app)

    with pytest.raises(ZeroDivisionError):
        client.request("GET", "/Users")


def test_application_without_response_is_refused():
    """An application that does not call start_response does not follow PEP 3333."""

    def app(environ, start_response):
        return []

    client = WSGISCIMClient(app)

    with pytest.raises(RuntimeError, match="did not call 'start_response'"):
        client.request("GET", "/Users")


def test_body_written_and_returned_is_joined():
    """The body written with the write callable comes before the returned body."""

    def app(environ, start_response):
        write = start_response("200 OK", [])
        write(b"foo")
        return [b"bar", b"baz"]

    client = WSGISCIMClient(app)

    assert client.request("GET", "/Users").content == b"foobarbaz"


def test_response_iterable_is_closed():
    """The close method of the response iterable is called (PEP 3333)."""
    closed = []

    class Body:
        def __iter__(self):
            yield b"foo"

        def close(self):
            closed.append(True)

    def app(environ, start_response):
        start_response("200 OK", [])
        return Body()

    client = WSGISCIMClient(app)

    assert client.request("GET", "/Users").content == b"foo"
    assert closed == [True]


def test_response_restarted_after_an_error_replaces_the_headers():
    """An application calling start_response again after an error sends the new status."""

    def app(environ, start_response):
        start_response("200 OK", [("X-Test", "foo")])
        try:
            raise ZeroDivisionError()
        except ZeroDivisionError:
            start_response("500 Internal Server Error", [], sys.exc_info())
        return [b"error"]

    client = WSGISCIMClient(app)
    response = client.request("GET", "/Users")

    assert response.status_code == 500
    assert response.headers.get("X-Test") is None


def test_absolute_endpoint_under_the_base_url_is_requested():
    """An endpoint pointing back to the base URL reaches the application."""
    resource_type = ResourceType.from_resource(Group)
    resource_type.endpoint = "http://localhost/v2/Groups"
    provider = ScimProvider(models=[Group], resource_types=[resource_type])
    app = WSGIApplication(InMemoryStorage(), load_default_provider())
    client = WSGISCIMClient(app, base_url="http://localhost/v2", provider=provider)

    group = client.create(Group(display_name="admins"))

    assert client.query(Group, group.id).display_name == "admins"
