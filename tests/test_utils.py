import pytest
from scim2_models import EnterpriseUser
from scim2_models import Group
from scim2_models import InvalidValueException
from scim2_models import Resource
from scim2_models import ResourceType
from scim2_models import Schema
from scim2_models import ServiceProviderConfig
from scim2_models import User

from scim2_client.engines.httpx import SyncSCIMClient


def test_guess_resource_endpoint():
    class Foobar(Resource):
        __schema__ = "urn:ietf:params:scim:schemas:core:2.0:Foobar"

    client = SyncSCIMClient(
        None,
        resource_models=[User[EnterpriseUser], Group],
        resource_types=[
            ResourceType.from_resource(User[EnterpriseUser]),
            ResourceType.from_resource(Group),
        ],
    )
    assert client.resource_endpoint(Group) == "/Groups"
    assert client.resource_endpoint(User) == "/Users"
    assert client.resource_endpoint(ResourceType) == "/ResourceTypes"
    assert client.resource_endpoint(Schema) == "/Schemas"
    assert client.resource_endpoint(User[EnterpriseUser]) == "/Users"

    # This one is special as it does not take an ending 's'
    assert client.resource_endpoint(ServiceProviderConfig) == "/ServiceProviderConfig"

    with pytest.raises(InvalidValueException):
        client.resource_endpoint(Foobar)


def test_get_resource_model():
    client = SyncSCIMClient(
        None,
        resource_models=[User[EnterpriseUser]],
    )
    assert client.get_resource_model("User") == User[EnterpriseUser]
    assert (
        client.get_resource_model("urn:ietf:params:scim:schemas:core:2.0:User")
        == User[EnterpriseUser]
    )
    assert client.get_resource_model("Group") is None
