import threading
import wsgiref.simple_server

import portpicker
import pytest
from scim2_models import EnterpriseUser
from scim2_models import Extension
from scim2_models import Group
from scim2_models import ResourceType
from scim2_models import ScimProvider
from scim2_models import User

from scim2_client.engines.httpx2 import Client
from scim2_client.engines.httpx2 import SyncSCIMClient

scim2_server = pytest.importorskip("scim2_server")
from scim2_server.applications.wsgi import WSGIApplication  # noqa: E402
from scim2_server.memory import InMemoryStorage  # noqa: E402


class OtherExtension(Extension):
    __schema__ = "urn:ietf:params:scim:schemas:extension:Other:1.0:User"

    test: str | None = None
    test2: list[str] | None = None


@pytest.fixture(scope="session")
def server():
    provider = ScimProvider(
        models=[User, EnterpriseUser, OtherExtension, Group],
        resource_types=[
            ResourceType.from_resource(User[EnterpriseUser | OtherExtension]),
            ResourceType.from_resource(Group),
        ],
    )
    app = WSGIApplication(InMemoryStorage(), provider)

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


def test_discovery_resource_types_multiple_extensions(server):
    host, port = server
    client = Client(base_url=f"http://{host}:{port}")
    scim_client = SyncSCIMClient(client)

    scim_client.discover()
    assert scim_client.get_resource_model("User")
    assert scim_client.get_resource_model("Group")

    # Try to create a user to see if discover filled everything correctly
    user_request = User[EnterpriseUser | OtherExtension](
        user_name="bjensen@example.com"
    )
    scim_client.create(user_request)
