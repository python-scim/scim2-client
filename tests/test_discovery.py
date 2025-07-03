import threading
import wsgiref.simple_server
from typing import Annotated
from typing import Union

import portpicker
import pytest
from httpx import Client
from scim2_models import EnterpriseUser
from scim2_models import Extension
from scim2_models import Group
from scim2_models import Meta
from scim2_models import Required
from scim2_models import ResourceType
from scim2_models import User

from scim2_client.engines.httpx import SyncSCIMClient

scim2_server = pytest.importorskip("scim2_server")
from scim2_server.backend import InMemoryBackend  # noqa: E402
from scim2_server.provider import SCIMProvider  # noqa: E402


class OtherExtension(Extension):
    schemas: Annotated[list[str], Required.true] = [
        "urn:ietf:params:scim:schemas:extension:Other:1.0:User"
    ]

    test: str | None = None
    test2: list[str] | None = None


def get_schemas():
    schemas = [
        User.to_schema(),
        Group.to_schema(),
        OtherExtension.to_schema(),
        EnterpriseUser.to_schema(),
    ]

    # SCIMProvider register_schema requires meta object to be set
    for schema in schemas:
        schema.meta = Meta(resource_type="Schema")

    return schemas


def get_resource_types():
    resource_types = [
        ResourceType.from_resource(User[Union[EnterpriseUser, OtherExtension]]),
        ResourceType.from_resource(Group),
    ]

    # SCIMProvider register_resource_type requires meta object to be set
    for resource_type in resource_types:
        resource_type.meta = Meta(resource_type="ResourceType")

    return resource_types


@pytest.fixture(scope="session")
def server():
    backend = InMemoryBackend()
    provider = SCIMProvider(backend)
    for schema in get_schemas():
        provider.register_schema(schema)
    for resource_type in get_resource_types():
        provider.register_resource_type(resource_type)

    host = "localhost"
    port = portpicker.pick_unused_port()
    httpd = wsgiref.simple_server.make_server(host, port, provider)

    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.start()
    try:
        yield host, port
    finally:
        httpd.shutdown()
        server_thread.join()


def test_discovery_resource_types_multiple_extensions(server):
    host, port = server
    client = Client(base_url=f"http://{host}:{port}")
    scim_client = SyncSCIMClient(client)

    scim_client.discover()
    assert scim_client.get_resource_model("User")
    assert scim_client.get_resource_model("Group")

    # Try to create a user to see if discover filled everything correctly
    user_request = User[Union[EnterpriseUser, OtherExtension]](user_name="bjensen@example.com")
    scim_client.create(user_request)
