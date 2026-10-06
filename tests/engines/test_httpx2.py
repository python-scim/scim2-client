import threading
import wsgiref.simple_server

import portpicker
import pytest
from scim2_models import BulkOperation
from scim2_models import BulkRequest
from scim2_models import PatchOp
from scim2_models import PatchOperation
from scim2_models import SCIMException
from scim2_models import ScimProvider
from scim2_models import SearchRequest
from scim2_models import ServiceProviderConfig
from scim2_models import User

from scim2_client import RequestNetworkException
from scim2_client.engines.httpx2 import AsyncClient
from scim2_client.engines.httpx2 import AsyncSCIMClient
from scim2_client.engines.httpx2 import Client
from scim2_client.engines.httpx2 import SyncSCIMClient

scim2_server = pytest.importorskip("scim2_server")
from scim2_server.applications.wsgi import WSGIApplication  # noqa: E402
from scim2_server.memory import InMemoryStorage  # noqa: E402
from scim2_server.utils import load_default_provider  # noqa: E402


@pytest.fixture(scope="session")
def server():
    app = WSGIApplication(InMemoryStorage(), load_default_provider())
    host = "localhost"
    port = portpicker.pick_unused_port()
    httpd = wsgiref.simple_server.make_server(host, port, app)

    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.start()
    try:
        yield host, port
    finally:
        httpd.shutdown()
        server_thread.join()


def test_sync_engine(server):
    host, port = server
    client = Client(base_url=f"http://{host}:{port}")
    scim_client = SyncSCIMClient(client)

    scim_client.discover(
        schemas=False, resource_types=False, service_provider_config=False
    )
    assert not scim_client.provider.models
    assert not scim_client.provider.resource_types
    assert not scim_client.provider.config

    scim_client.discover()
    assert isinstance(scim_client.provider.config, ServiceProviderConfig)
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
        op=PatchOperation.Op.replace_, path="displayName", value="patched name"
    )
    patch_op = PatchOp[User](operations=[operation])
    scim_client.modify(User, response_user.id, patch_op)

    # Verify patch result with query
    queried_user = scim_client.query(User, response_user.id)
    assert queried_user.display_name == "patched name"

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


async def test_async_engine(server):
    host, port = server
    client = AsyncClient(base_url=f"http://{host}:{port}")
    scim_client = AsyncSCIMClient(client)

    await scim_client.discover(
        schemas=False, resource_types=False, service_provider_config=False
    )
    assert not scim_client.provider.models
    assert not scim_client.provider.resource_types
    assert not scim_client.provider.config

    await scim_client.discover()
    assert isinstance(scim_client.provider.config, ServiceProviderConfig)
    User = scim_client.get_resource_model("User")

    request_user = User(user_name="async_foo", display_name="async_bar")
    response_user = await scim_client.create(request_user)
    assert response_user.user_name == "async_foo"
    assert response_user.display_name == "async_bar"

    response_user = await scim_client.query(User, response_user.id)
    assert response_user.user_name == "async_foo"
    assert response_user.display_name == "async_bar"

    req = SearchRequest()
    response_users = await scim_client.search(req)
    # Find our user among all users
    our_user = next(u for u in response_users.resources if u.user_name == "async_foo")
    assert our_user.user_name == "async_foo"
    assert our_user.display_name == "async_bar"

    request_user = User(
        id=response_user.id, user_name="async_foo", display_name="async_baz"
    )
    response_user = await scim_client.replace(request_user)
    assert response_user.user_name == "async_foo"
    assert response_user.display_name == "async_baz"

    response_user = await scim_client.query(User, response_user.id)
    assert response_user.user_name == "async_foo"
    assert response_user.display_name == "async_baz"

    # Test patch operation followed by query
    operation = PatchOperation(
        op=PatchOperation.Op.replace_, path="displayName", value="async patched name"
    )
    patch_op = PatchOp[User](operations=[operation])
    await scim_client.modify(User, response_user.id, patch_op)

    # Verify patch result with query
    queried_user = await scim_client.query(User, response_user.id)
    assert queried_user.display_name == "async patched name"

    await scim_client.delete(User, response_user.id)
    with pytest.raises(SCIMException):
        await scim_client.query(User, response_user.id)

    response = await scim_client.bulk(
        BulkRequest[User](
            operations=[
                BulkOperation[User](
                    method="POST",
                    path="/Users",
                    bulk_id="qwerty",
                    data=User(user_name="Bob"),
                )
            ]
        )
    )
    (operation,) = response.operations
    assert operation.status == 201
    assert operation.bulk_id == "qwerty"
    created_user = await scim_client.query(User, operation.location.rsplit("/", 1)[-1])
    assert created_user.user_name == "Bob"


def test_sync_engine_request(server):
    """A raw request reaches the server and returns its response as is."""
    host, port = server
    client = Client(base_url=f"http://{host}:{port}")
    scim_client = SyncSCIMClient(client)

    response = scim_client.request("DELETE", "/Schemas")

    assert response.status_code == 405


async def test_async_engine_request(server):
    """A raw asynchronous request reaches the server and returns its response as is."""
    host, port = server
    client = AsyncClient(base_url=f"http://{host}:{port}")
    scim_client = AsyncSCIMClient(client)

    response = await scim_client.request("DELETE", "/Schemas")

    assert response.status_code == 405


def test_sync_engine_request_network_error():
    """A raw request that cannot be sent raises RequestNetworkException."""
    scim_client = SyncSCIMClient(Client(base_url="http://invalid.test"))

    with pytest.raises(RequestNetworkException):
        scim_client.request("GET", "/Schemas")


async def test_async_engine_request_network_error():
    """A raw asynchronous request that cannot be sent raises RequestNetworkException."""
    scim_client = AsyncSCIMClient(AsyncClient(base_url="http://invalid.test"))

    with pytest.raises(RequestNetworkException):
        await scim_client.request("GET", "/Schemas")


def test_sync_engine_network_error_carries_the_request_payload():
    """A request that cannot be sent raises an error carrying the request payload."""
    scim_client = SyncSCIMClient(
        Client(base_url="http://invalid.test"), provider=ScimProvider(models=[User])
    )

    with pytest.raises(RequestNetworkException) as excinfo:
        scim_client.create(User(user_name="bjensen"))

    assert excinfo.value.source["userName"] == "bjensen"


async def test_async_engine_network_error_carries_the_request_payload():
    """An asynchronous request that cannot be sent raises an error carrying the request payload."""
    scim_client = AsyncSCIMClient(
        AsyncClient(base_url="http://invalid.test"),
        provider=ScimProvider(models=[User]),
    )

    with pytest.raises(RequestNetworkException) as excinfo:
        await scim_client.create(User(user_name="bjensen"))

    assert excinfo.value.source["userName"] == "bjensen"
