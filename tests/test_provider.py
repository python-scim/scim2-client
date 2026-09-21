"""The description of the service a client talks to."""

import pytest
from scim2_models import URI
from scim2_models import Context
from scim2_models import EnterpriseUser
from scim2_models import Group
from scim2_models import ListResponse
from scim2_models import Patch
from scim2_models import Reference
from scim2_models import ResourceType
from scim2_models import Schema
from scim2_models import SchemaExtension
from scim2_models import ScimProvider
from scim2_models import ServiceProviderConfig
from scim2_models import User

from scim2_client import InvalidServiceDescriptionException
from scim2_client.engines.httpx2 import Client
from scim2_client.engines.httpx2 import SyncSCIMClient


def list_payload(resources):
    """Render resources as the list response an endpoint answers."""
    model = ListResponse[type(resources[0])]
    return model(total_results=len(resources), resources=resources).model_dump(
        scim_ctx=Context.RESOURCE_QUERY_RESPONSE
    )


@pytest.fixture
def service(httpserver):
    """Return a factory for clients bound to a server publishing a description."""

    def factory(schemas, resource_types, config=None, provider=None):
        httpserver.expect_request("/Schemas").respond_with_json(
            list_payload(schemas), content_type="application/scim+json"
        )
        httpserver.expect_request("/ResourceTypes").respond_with_json(
            list_payload(resource_types), content_type="application/scim+json"
        )
        httpserver.expect_request("/ServiceProviderConfig").respond_with_json(
            (config or ServiceProviderConfig()).model_dump(
                scim_ctx=Context.RESOURCE_QUERY_RESPONSE
            ),
            content_type="application/scim+json",
        )
        return SyncSCIMClient(
            Client(base_url=f"http://localhost:{httpserver.port}"), provider=provider
        )

    return factory


def test_endpoints_are_derived_when_no_resource_type_is_known():
    """Test that a provider given no resource type builds naive endpoints."""
    client = SyncSCIMClient(None, provider=ScimProvider(models=[User, Group]))

    assert client.resource_endpoint(User) == "/Users"
    assert client.resource_endpoint(Group) == "/Groups"


def test_resource_types_bind_the_extensions_to_their_resource():
    """Test that the client serves the model a resource type composes."""
    client = SyncSCIMClient(
        None,
        provider=ScimProvider(
            models=[User, EnterpriseUser],
            resource_types=[ResourceType.from_resource(User[EnterpriseUser])],
        ),
    )

    assert client.get_resource_model("User") is User[EnterpriseUser]
    assert (
        client.get_resource_model("urn:ietf:params:scim:schemas:core:2.0:User")
        is User[EnterpriseUser]
    )


def test_extensions_are_not_resources():
    """Test that an extension is not a model the client can query."""
    client = SyncSCIMClient(
        None,
        provider=ScimProvider(
            models=[User, EnterpriseUser],
            resource_types=[ResourceType.from_resource(User[EnterpriseUser])],
        ),
    )

    assert (
        client.get_resource_model(
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        )
        is None
    )


def test_configuration_resources_are_always_known():
    """Test that the resources of RFC7644 §4 need no declaration."""
    client = SyncSCIMClient(None, provider=ScimProvider(models=[User]))

    assert client.get_resource_model("Schema") is Schema
    assert client.get_resource_model("Foobar") is None


def test_two_resource_types_may_serve_a_same_schema():
    """Test that two endpoints built upon a same schema are told apart."""
    staff = ResourceType(
        id="Staff",
        name="Staff",
        endpoint=Reference[URI]("/Staff"),
        schema_=Reference[URI](str(User.__schema__)),
        schema_extensions=[
            SchemaExtension(schema_=Reference[URI](str(EnterpriseUser.__schema__)))
        ],
    )
    client = SyncSCIMClient(
        None,
        provider=ScimProvider(
            models=[User, EnterpriseUser],
            resource_types=[ResourceType.from_resource(User), staff],
        ),
    )

    assert client.get_resource_model("User") is User
    assert client.get_resource_model("Staff") is User[EnterpriseUser]
    assert client.resource_endpoint(User) == "/Users"
    assert client.resource_endpoint(User[EnterpriseUser]) == "/Staff"


def test_provider_and_described_objects_are_exclusive():
    """Test that the server is described either by a provider or by the old parameters."""
    with pytest.raises(TypeError, match="Cannot pass both 'provider'"):
        SyncSCIMClient(
            None, provider=ScimProvider(models=[User]), resource_models=[Group]
        )


def test_discovery_describes_the_service(service):
    """Test that a client discovers the models and the capabilities of a server."""
    client = service(
        schemas=[User.to_schema(), EnterpriseUser.to_schema()],
        resource_types=[ResourceType.from_resource(User[EnterpriseUser])],
        config=ServiceProviderConfig(patch=Patch(supported=True)),
    )

    client.discover()

    assert client.get_resource_model("User") is not None
    assert client.resource_endpoint(client.get_resource_model("User")) == "/Users"
    assert client.provider.config.patch.supported


def test_discovery_completes_the_known_models(service):
    """Test that the models the client was given are kept over those a server publishes."""
    client = service(
        schemas=[User.to_schema(), Group.to_schema()],
        resource_types=[
            ResourceType.from_resource(User),
            ResourceType.from_resource(Group),
        ],
        provider=ScimProvider(models=[User]),
    )

    client.discover()

    assert client.get_resource_model("User") is User
    assert client.get_resource_model("Group") is None
    assert client.provider.config is not None


def test_discovery_keeps_the_declared_capabilities(service):
    """Test that the capabilities the client was given are kept over those a server publishes."""
    client = service(
        schemas=[User.to_schema()],
        resource_types=[ResourceType.from_resource(User)],
        config=ServiceProviderConfig(patch=Patch(supported=True)),
        provider=ScimProvider(
            config=ServiceProviderConfig(patch=Patch(supported=False))
        ),
    )

    client.discover()

    assert client.get_resource_model("User") is not None
    assert client.provider.config.patch.supported is False


def test_incoherent_service_description(service):
    """Test that a server serving a resource type it describes nowhere is refused."""
    client = service(
        schemas=[User.to_schema()],
        resource_types=[
            ResourceType.from_resource(User),
            ResourceType.from_resource(Group),
        ],
    )

    with pytest.raises(InvalidServiceDescriptionException, match="No resource"):
        client.discover()
