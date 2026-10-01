from typing import Any

import pytest
from httpx2 import Client
from httpx2 import Response
from httpx2 import WSGITransport
from scim2_models import PatchOp
from scim2_models import PatchOperation
from scim2_models import SCIMException
from scim2_models import SearchRequest

from scim2_client import BaseSyncSCIMClient

scim2_server = pytest.importorskip("scim2_server")
from scim2_server.backend import InMemoryBackend  # noqa: E402
from scim2_server.provider import SCIMApplication  # noqa: E402
from scim2_server.utils import load_default_provider  # noqa: E402


class RequestOnlySCIMClient(BaseSyncSCIMClient):
    """An engine that only knows how to send a request."""

    def __init__(self, client: Client, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.client = client

    def request(self, method: str, url: str, **kwargs: Any) -> Response:
        return self.client.request(method, url, **kwargs)


def test_engine_only_implementing_request():
    """An engine implementing only the request method performs every SCIM operation."""
    app = SCIMApplication(InMemoryBackend(), load_default_provider())
    client = Client(base_url="http://scim.test", transport=WSGITransport(app=app))
    scim_client = RequestOnlySCIMClient(client)
    scim_client.discover()
    User = scim_client.get_resource_model("User")

    user = scim_client.create(User(user_name="bjensen"))
    assert scim_client.query(User, user.id).user_name == "bjensen"

    users = scim_client.search(User, SearchRequest(filter='userName eq "bjensen"'))
    assert [found.id for found in users.resources] == [user.id]

    replaced = scim_client.replace(
        User(id=user.id, user_name="bjensen", display_name="Babs")
    )
    assert replaced.display_name == "Babs"

    patch_op = PatchOp[User](
        operations=[
            PatchOperation(
                op=PatchOperation.Op.replace_, path="displayName", value="Barbara"
            )
        ]
    )
    scim_client.modify(User, user.id, patch_op)
    assert scim_client.query(User, user.id).display_name == "Barbara"

    scim_client.delete(User, user.id)
    with pytest.raises(SCIMException):
        scim_client.query(User, user.id)
