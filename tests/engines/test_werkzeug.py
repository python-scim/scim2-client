import pytest
from scim2_models import BulkOperation
from scim2_models import BulkRequest
from scim2_models import PatchOp
from scim2_models import PatchOperation
from scim2_models import ResponseParameters
from scim2_models import SCIMException
from scim2_models import ScimProvider
from scim2_models import SearchRequest
from scim2_models import User
from werkzeug.test import Client
from werkzeug.wrappers import Request
from werkzeug.wrappers import Response

from scim2_client.engines.werkzeug import TestSCIMClient
from scim2_client.errors import UnexpectedContentFormatException

scim2_server = pytest.importorskip("scim2_server")
from scim2_server.backend import InMemoryBackend  # noqa: E402
from scim2_server.provider import SCIMApplication  # noqa: E402
from scim2_server.utils import load_default_provider  # noqa: E402


@pytest.fixture
def scim_app():
    return SCIMApplication(InMemoryBackend(), load_default_provider())


@pytest.fixture
def scim_client(scim_app):
    werkzeug_client = Client(scim_app)
    scim_client = TestSCIMClient(werkzeug_client)
    scim_client.discover()
    return scim_client


def test_werkzeug_engine(scim_client):
    User = scim_client.get_resource_model("User")
    request_user = User(user_name="foo", display_name="bar")
    response_user = scim_client.create(request_user)
    assert response_user.user_name == "foo"
    assert response_user.display_name == "bar"

    response_user = scim_client.query(User, response_user.id)
    assert response_user.user_name == "foo"
    assert response_user.display_name == "bar"

    req = SearchRequest()
    response_users = scim_client.search(req)
    assert response_users.resources[0].user_name == "foo"
    assert response_users.resources[0].display_name == "bar"

    request_user = User(id=response_user.id, user_name="foo", display_name="baz")
    response_user = scim_client.replace(request_user)
    assert response_user.user_name == "foo"
    assert response_user.display_name == "baz"

    response_user = scim_client.query(User, response_user.id)
    assert response_user.user_name == "foo"
    assert response_user.display_name == "baz"

    # Test patch operation followed by query
    operation = PatchOperation(
        op=PatchOperation.Op.replace_, path="displayName", value="werkzeug patched"
    )
    patch_op = PatchOp[User](operations=[operation])
    scim_client.modify(User, response_user.id, patch_op)

    # Verify patch result with query
    queried_user = scim_client.query(User, response_user.id)
    assert queried_user.display_name == "werkzeug patched"

    scim_client.delete(User, response_user.id)
    with pytest.raises(SCIMException):
        scim_client.query(User, response_user.id)

    response = scim_client.bulk(
        BulkRequest[User](
            operations=[
                BulkOperation[User](
                    method="POST",
                    path="/Users",
                    bulk_id="qwerty",
                    data=User(user_name="Alice"),
                )
            ]
        )
    )
    (operation,) = response.operations
    assert operation.status == 201
    assert operation.bulk_id == "qwerty"
    created_user = scim_client.query(User, operation.location.rsplit("/", 1)[-1])
    assert created_user.user_name == "Alice"


def test_werkzeug_query_with_attributes(scim_client):
    """List query parameters like attributes are correctly serialized in the query string."""
    User = scim_client.get_resource_model("User")
    request_user = User(user_name="foo", display_name="bar", title="Engineer")
    response_user = scim_client.create(request_user)

    params = ResponseParameters(attributes=["displayName"])
    result = scim_client.query(User, response_user.id, query_parameters=params)
    assert result.display_name == "bar"
    assert result.title is None


def test_no_json():
    """Test that pages that do not return JSON raise an UnexpectedContentFormatException error."""

    @Request.application
    def application(request):
        return Response("Hello, World!", content_type="application/scim+json")

    werkzeug_client = Client(application)
    scim_client = TestSCIMClient(
        client=werkzeug_client, provider=ScimProvider(models=[User])
    )
    with pytest.raises(UnexpectedContentFormatException):
        scim_client.query(url="/")


def test_invalid_payload():
    """Test that a response with invalid SCIM payload raises a ResponsePayloadValidationException."""
    from scim2_client.errors import ResponsePayloadValidationException

    @Request.application
    def application(request):
        # Return valid JSON but with invalid SCIM data (missing required fields)
        return Response(
            '{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "active": "not-a-bool"}',
            content_type="application/scim+json",
        )

    werkzeug_client = Client(application)
    scim_client = TestSCIMClient(
        client=werkzeug_client, provider=ScimProvider(models=[User])
    )
    with pytest.raises(ResponsePayloadValidationException):
        scim_client.query(url="/Users/1234")


def test_environ(scim_client):
    @Request.application
    def application(request):
        assert request.headers["content-type"] == "foobar"
        user = User(user_name="foobar", id="foobar")
        return Response(user.model_dump_json(), content_type="application/scim+json")

    werkzeug_client = Client(application)
    scim_client = TestSCIMClient(
        client=werkzeug_client,
        environ={"headers": {"content-type": "foobar"}},
        provider=ScimProvider(models=[User]),
    )
    scim_client.query(url="/Users")


def test_request(scim_client):
    """A raw request reaches the application and returns its response as is."""
    response = scim_client.request("DELETE", "/Schemas")

    assert response.status_code == 405


def test_request_with_prefix_and_environ():
    """A raw request is sent under the SCIM prefix, with the client environ."""

    @Request.application
    def application(request):
        return Response(
            f"{request.method} {request.path} {request.headers['X-Test']}", status=405
        )

    scim_client = TestSCIMClient(
        client=Client(application),
        environ={"headers": {"X-Test": "foobar"}},
        scim_prefix="/scim/v2",
    )

    response = scim_client.request("DELETE", "/Schemas")

    assert response.status_code == 405
    assert response.text == "DELETE /scim/v2/Schemas foobar"


def test_request_headers_extend_environ_headers():
    """Headers passed to a request are sent along with the headers of the client environ."""

    @Request.application
    def application(request):
        return Response(f"{request.headers['X-Test']} {request.headers['If-Match']}")

    scim_client = TestSCIMClient(
        client=Client(application),
        environ={"headers": {"X-Test": "foobar"}},
    )

    response = scim_client.request("GET", "/Users", headers={"If-Match": '"1"'})

    assert response.text == 'foobar "1"'


def test_request_headers_override_environ_headers():
    """A header passed to a request replaces the client environ header of the same name."""

    @Request.application
    def application(request):
        return Response(",".join(request.headers.getlist("X-Test")))

    scim_client = TestSCIMClient(
        client=Client(application),
        environ={"headers": [("X-Test", "foo"), ("X-Other", "bar")]},
    )

    response = scim_client.request("GET", "/Users", headers={"x-test": "baz"})

    assert response.text == "baz"
