import pytest
from scim2_models import EnterpriseUser
from scim2_models import Group
from scim2_models import Patch
from scim2_models import ResourceType
from scim2_models import ScimProvider
from scim2_models import ServiceProviderConfig
from scim2_models import User

from scim2_client.engines.httpx2 import SyncSCIMClient


def test_described_objects_parameters_are_deprecated():
    """Test that the objects describing a server are passed as a provider."""
    with pytest.warns(DeprecationWarning, match="parameters are deprecated"):
        client = SyncSCIMClient(None, resource_models=[User[EnterpriseUser]])

    assert client.provider.models == (User, EnterpriseUser)
    assert client.get_resource_model("User") is User[EnterpriseUser]


def test_described_objects_attributes_are_deprecated():
    """Test that the objects describing a server are read on the provider."""
    client = SyncSCIMClient(None, provider=ScimProvider(models=[User]))

    with pytest.warns(DeprecationWarning, match="'resource_models' is deprecated"):
        assert client.resource_models == (User,)

    with pytest.warns(DeprecationWarning, match="'resource_types' is deprecated"):
        assert len(client.resource_types) == 1

    with pytest.warns(
        DeprecationWarning, match="'service_provider_config' is deprecated"
    ):
        assert client.service_provider_config is None


def test_described_objects_are_assigned_one_by_one():
    """Test that a server can be described by successive assignments."""
    client = SyncSCIMClient(None)

    with pytest.warns(DeprecationWarning):
        client.service_provider_config = ServiceProviderConfig(
            patch=Patch(supported=True)
        )

    with pytest.warns(DeprecationWarning):
        client.resource_types = [ResourceType.from_resource(User[EnterpriseUser])]

    with pytest.warns(DeprecationWarning):
        assert not client.resource_models

    with pytest.warns(DeprecationWarning):
        client.resource_models = [User[EnterpriseUser]]

    assert client.get_resource_model("User") is User[EnterpriseUser]
    assert client.provider.config.patch.supported


def test_naive_resource_types_registration_is_deprecated():
    """Test that naive resource types are built without being asked for."""
    client = SyncSCIMClient(None, provider=ScimProvider(models=[User]))

    with pytest.warns(DeprecationWarning, match="'register_naive_resource_types'"):
        client.register_naive_resource_types()

    assert client.resource_endpoint(User) == "/Users"


def test_resource_models_building_is_deprecated():
    """Test that models are built from the objects a server publishes."""
    client = SyncSCIMClient(None)

    with pytest.warns(DeprecationWarning, match="'build_resource_models'"):
        models = client.build_resource_models(
            [ResourceType.from_resource(User[EnterpriseUser])],
            [User.to_schema(), EnterpriseUser.to_schema()],
        )

    assert len(models) == 1
    assert models[0].get_extension_models()


def test_naive_endpoints_follow_the_models():
    """Test that endpoints nobody declared are rebuilt when the models change."""
    with pytest.warns(DeprecationWarning):
        client = SyncSCIMClient(None, resource_models=[User])

    with pytest.warns(DeprecationWarning):
        client.resource_models = [Group]

    assert client.resource_endpoint(Group) == "/Groups"
