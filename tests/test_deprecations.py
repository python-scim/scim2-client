import pytest
from scim2_models import EnterpriseUser
from scim2_models import Group
from scim2_models import Patch
from scim2_models import ResourceType
from scim2_models import ScimProvider
from scim2_models import ServiceProviderConfig
from scim2_models import User

import scim2_client
from scim2_client import errors
from scim2_client.engines.httpx2 import SyncSCIMClient

RENAMED_EXCEPTIONS = [
    ("SCIMClientError", "SCIMClientException"),
    ("SCIMResponseError", "SCIMResponseException"),
    ("RequestNetworkError", "RequestNetworkException"),
    ("UnexpectedStatusCode", "UnexpectedStatusCodeException"),
    ("UnexpectedContentType", "UnexpectedContentTypeException"),
    ("UnexpectedContentFormat", "UnexpectedContentFormatException"),
    ("ResponsePayloadValidationError", "ResponsePayloadValidationException"),
]


@pytest.mark.parametrize(("old", "new"), RENAMED_EXCEPTIONS)
@pytest.mark.parametrize("module", [scim2_client, errors])
def test_old_exception_names_are_the_renamed_classes(module, old, new):
    """Test that the old exception names warn about the rename and point at the new classes."""
    with pytest.warns(DeprecationWarning, match=f"{old} is deprecated, use {new}"):
        alias = getattr(module, old)

    assert alias is getattr(module, new)


@pytest.mark.parametrize("module", [scim2_client, errors])
def test_unknown_names_are_not_served(module):
    """Test that names that were never part of the API are still unknown."""
    unknown_name = "Foobar"
    with pytest.raises(AttributeError, match="has no attribute 'Foobar'"):
        getattr(module, unknown_name)


def test_old_exception_names_catch_the_exceptions_the_client_raises(
    httpserver, sync_client
):
    """Test that code written against the old names still catches the client exceptions."""
    httpserver.expect_request("/Users").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
        },
        status=299,
    )

    with pytest.warns(DeprecationWarning):
        unexpected_status_code = errors.UnexpectedStatusCode

    with pytest.raises(unexpected_status_code):
        sync_client.create(User(user_name="bjensen@example.com"))


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
