import pytest
from scim2_models import PatchOp
from scim2_models import PatchOperation
from scim2_models import SearchRequest
from scim2_models import User
from werkzeug.test import Client
from werkzeug.wrappers import Request
from werkzeug.wrappers import Response

from scim2_client.engines.werkzeug import TestSCIMClient
from scim2_client.errors import SCIMResponseErrorObject
from scim2_client.errors import UnexpectedContentFormat

scim2_server = pytest.importorskip("scim2_server")
from scim2_server.backend import InMemoryBackend  # noqa: E402
from scim2_server.provider import SCIMProvider  # noqa: E402
from scim2_server.utils import load_default_resource_types  # noqa: E402
from scim2_server.utils import load_default_schemas  # noqa: E402


@pytest.fixture
def scim_provider():
    provider = SCIMProvider(InMemoryBackend())
    for schema in load_default_schemas().values():
        provider.register_schema(schema)
    for resource_type in load_default_resource_types().values():
        provider.register_resource_type(resource_type)
    return provider


@pytest.fixture
def scim_client(scim_provider):
    werkzeug_client = Client(scim_provider)
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
    with pytest.raises(SCIMResponseErrorObject):
        scim_client.query(User, response_user.id)


def test_no_json():
    """Test that pages that do not return JSON raise an UnexpectedContentFormat error."""

    @Request.application
    def application(request):
        return Response("Hello, World!", content_type="application/scim+json")

    werkzeug_client = Client(application)
    scim_client = TestSCIMClient(client=werkzeug_client, resource_models=(User,))
    scim_client.register_naive_resource_types()
    with pytest.raises(UnexpectedContentFormat):
        scim_client.query(url="/")


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
        resource_models=(User,),
    )
    scim_client.register_naive_resource_types()
    scim_client.query(url="/Users")
