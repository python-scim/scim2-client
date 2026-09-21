import pytest
from scim2_models import Group
from scim2_models import PatchOp
from scim2_models import PatchOperation
from scim2_models import ScimProvider
from scim2_models import User

from scim2_client.engines.httpx2 import Client
from scim2_client.engines.httpx2 import SyncSCIMClient


@pytest.fixture
def sync_client(httpserver):
    with Client(base_url=f"http://localhost:{httpserver.port}") as client:
        scim_client = SyncSCIMClient(
            client,
            provider=ScimProvider(models=[User, Group]),
        )
        yield scim_client


@pytest.fixture
def user():
    """Return a registered user, as the server would send it."""
    return User(
        id="2819c223-7f76-453a-919d-413861904646", user_name="bjensen@example.com"
    )


@pytest.fixture
def patch_op():
    """Return a patch operation setting the display name of a user."""
    return PatchOp[User](
        operations=[
            PatchOperation(
                op=PatchOperation.Op.replace_,
                path="displayName",
                value="Updated Display Name",
            )
        ]
    )
