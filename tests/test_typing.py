"""The client methods are typed after the resources they are called with."""

from typing import TYPE_CHECKING
from typing import Any
from typing import assert_type

import pytest
from scim2_models import EnterpriseUser
from scim2_models import Error
from scim2_models import Group
from scim2_models import ListResponse
from scim2_models import PatchOp
from scim2_models import Resource
from scim2_models import ResourceType
from scim2_models import Schema
from scim2_models import ScimProvider
from scim2_models import SearchRequest
from scim2_models import ServiceProviderConfig
from scim2_models import User

from scim2_client import BaseAsyncSCIMClient
from scim2_client import Me
from scim2_client.engines.wsgi import WSGISCIMClient

scim2_server = pytest.importorskip("scim2_server")
from scim2_server.applications.wsgi import WSGIApplication  # noqa: E402
from scim2_server.memory import InMemoryStorage  # noqa: E402
from scim2_server.requests import ScimRequest  # noqa: E402
from scim2_server.service import ScimService  # noqa: E402
from scim2_server.utils import load_default_provider  # noqa: E402

Raw = Error | dict[str, Any]


def client_provider() -> ScimProvider:
    """Describe the server with the scim2-models classes, so the client returns instances of them."""
    return ScimProvider(
        models=[User, EnterpriseUser, Group],
        resource_types=[
            ResourceType.from_resource(User[EnterpriseUser]),
            ResourceType.from_resource(Group),
        ],
    )


@pytest.fixture
def client() -> WSGISCIMClient:
    """Build a client with the scim2-models classes, so it returns instances of them."""
    app = WSGIApplication(InMemoryStorage(), load_default_provider())
    scim_client = WSGISCIMClient(app, provider=client_provider())
    scim_client.discover()
    return scim_client


@pytest.fixture
def user(client: WSGISCIMClient) -> User[Any]:
    created = client.create(User[Any](user_name="bjensen"))
    assert isinstance(created, User)
    return created


def test_query_with_a_model(client: WSGISCIMClient, user: User[Any]) -> None:
    """A model gives a resource with an id, and a list of resources without."""
    assert user.id
    found = assert_type(client.query(User[Any], user.id), User[Any] | Raw)
    assert isinstance(found, User)

    same = assert_type(client.query(User[Any], user), User[Any] | Raw)
    assert isinstance(same, User)

    users = assert_type(client.query(User[Any]), ListResponse[User[Any]] | Raw)
    assert isinstance(users, ListResponse)

    params = {"attributes": ["userName"]}
    users = assert_type(client.query(User[Any], params), ListResponse[User[Any]] | Raw)
    assert isinstance(users, ListResponse)


def test_query_with_a_resource_object(client: WSGISCIMClient, user: User[Any]) -> None:
    """A resource object gives a resource of its own type."""
    found = assert_type(client.query(user), User[Any] | Raw)
    assert isinstance(found, User)


def test_query_with_a_resource_type(client: WSGISCIMClient, user: User[Any]) -> None:
    """A resource type gives untyped resources."""
    assert user.id
    found = assert_type(client.query("User", user.id), Resource[Any] | Raw)
    assert isinstance(found, User)

    user_type = client.query(ResourceType, "User")
    assert isinstance(user_type, ResourceType)
    users = assert_type(client.query(user_type), ListResponse[Resource[Any]] | Raw)
    assert isinstance(users, ListResponse)


def test_query_server_description(client: WSGISCIMClient) -> None:
    """The service provider configuration is a single object, the schemas a list."""
    config = assert_type(
        client.query(ServiceProviderConfig), ServiceProviderConfig | Raw
    )
    assert isinstance(config, ServiceProviderConfig)

    schemas = assert_type(client.query(Schema), ListResponse[Schema] | Raw)
    assert isinstance(schemas, ListResponse)


def test_search(client: WSGISCIMClient, user: User[Any]) -> None:
    """A search gives a list of the model it is called with."""
    request = SearchRequest[Any].model_validate({"filter": 'userName eq "bjensen"'})
    users = assert_type(
        client.search(User[Any], request), ListResponse[User[Any]] | Raw
    )
    assert isinstance(users, ListResponse)

    everything = assert_type(client.search(request), ListResponse[Resource[Any]] | Raw)
    assert isinstance(everything, ListResponse)


def test_create_and_replace(client: WSGISCIMClient, user: User[Any]) -> None:
    """A resource object or a model gives a resource of the same type."""
    created = assert_type(
        client.create(User[Any], {"userName": "alice"}), User[Any] | Raw
    )
    assert isinstance(created, User)

    created = assert_type(
        client.create("User", User[Any](user_name="bob")), User[Any] | Raw
    )
    assert isinstance(created, User)

    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "carol",
    }
    untyped = assert_type(client.create(payload), Resource[Any] | Raw)
    assert isinstance(untyped, User)

    user.display_name = "Babs"
    replaced = assert_type(client.replace(user), User[Any] | Raw)
    assert isinstance(replaced, User)


class MeService(ScimService):
    """Serve /Me with the user whose id is the subject."""

    def me_target(self, request: ScimRequest) -> tuple[ResourceType, str]:
        return self.get_resource_type("User"), request.subject

    def me_creation_type(self, request: ScimRequest) -> ResourceType:
        return self.get_resource_type("User")


class MeApplication(WSGIApplication):
    """Authenticate every client as the user of :attr:`subject`."""

    subject: str | None = None

    def get_subject(self, request: ScimRequest) -> str | None:
        return self.subject


def test_me() -> None:
    """Me reaches the resource of the authenticated client on a server serving /Me."""
    provider = load_default_provider()
    app = MeApplication(InMemoryStorage(), provider, MeService(provider))
    client = WSGISCIMClient(app, provider=client_provider())
    client.discover()

    created = assert_type(
        client.create(Me, User[Any](user_name="bjensen")), User[Any] | Raw
    )
    assert isinstance(created, User)
    assert created.id
    app.subject = created.id

    found = assert_type(client.query(Me), Resource[Any] | Raw)
    assert isinstance(found, User)
    assert found.user_name == "bjensen"

    found.display_name = "Babs"
    replaced = assert_type(client.replace(Me, found), User[Any] | Raw)
    assert isinstance(replaced, User)
    assert replaced.display_name == "Babs"

    patch_op = PatchOp[User[Any]].model_validate(
        {"Operations": [{"op": "replace", "path": "nickName", "value": "B"}]}
    )
    assert_type(client.modify(Me, patch_op), User[Any] | Raw | None)
    modified = client.query(Me)
    assert isinstance(modified, User)
    assert modified.nick_name == "B"

    assert client.delete(Me) is None
    gone = client.query(User[Any], created.id, raise_scim_errors=False)
    assert isinstance(gone, Error)
    assert gone.status == 404


if TYPE_CHECKING:

    async def check_async_client(client: BaseAsyncSCIMClient, user: User[Any]) -> None:
        assert_type(await client.query(User[Any], "123"), User[Any] | Raw)
        assert_type(await client.query(User[Any]), ListResponse[User[Any]] | Raw)
        assert_type(await client.query(user), User[Any] | Raw)
        assert_type(await client.query("User"), ListResponse[Resource[Any]] | Raw)
        assert_type(
            await client.query(ServiceProviderConfig), ServiceProviderConfig | Raw
        )
        assert_type(await client.search(User[Any]), ListResponse[User[Any]] | Raw)
        assert_type(await client.create(user), User[Any] | Raw)
        assert_type(await client.replace(User[Any], {}), User[Any] | Raw)
        assert_type(await client.create({}), Resource[Any] | Raw)
        assert_type(await client.query(Me), Resource[Any] | Raw)
        assert_type(await client.create(Me, user), User[Any] | Raw)
        assert_type(await client.replace(Me, user), User[Any] | Raw)
