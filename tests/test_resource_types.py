"""The resource type a request is sent to."""

import pytest
from scim2_models import URI
from scim2_models import EnterpriseUser
from scim2_models import Group
from scim2_models import InvalidValueException
from scim2_models import Meta
from scim2_models import PatchOp
from scim2_models import PatchOperation
from scim2_models import Reference
from scim2_models import Resource
from scim2_models import ResourceType
from scim2_models import ResponseParameters
from scim2_models import SchemaExtension
from scim2_models import ScimProvider
from scim2_models import SearchRequest
from scim2_models import User

from scim2_client.engines.httpx2 import Client
from scim2_client.engines.httpx2 import SyncSCIMClient

USER_ID = "2819c223-7f76-453a-919d-413861904646"
ENTERPRISE = str(EnterpriseUser.__schema__)


class Member(Resource):
    __schema__ = "urn:example:schemas:User"


def resource_type(name, endpoint, schema=User.__schema__, id=None, extensions=()):
    return ResourceType(
        id=id or name,
        name=name,
        endpoint=Reference[URI](endpoint),
        schema_=Reference[URI](str(schema)),
        schema_extensions=[
            SchemaExtension(schema_=Reference[URI](uri), required=required)
            for uri, required in extensions
        ]
        or None,
    )


EMPLOYEE = resource_type("Employee", "/Employees", id="employee-id")


def user_payload(resource_type="Employee", **kwargs):
    return {
        "schemas": [str(User.__schema__)],
        "id": USER_ID,
        "userName": "bjensen@example.com",
        "meta": {"resourceType": resource_type},
        **kwargs,
    }


@pytest.fixture
def make_client(httpserver):
    """Return a factory for clients describing a server with the given resource types."""
    clients = []

    def factory(*resource_types, models=(User, Group)):
        client = Client(base_url=f"http://localhost:{httpserver.port}")
        clients.append(client)
        provider = ScimProvider(models=models, resource_types=resource_types)
        return SyncSCIMClient(client, provider=provider)

    yield factory
    for client in clients:
        client.close()


@pytest.fixture
def client(make_client):
    """Return a client for a server serving users on /Users and on /Employees."""
    return make_client(ResourceType.from_resource(User), EMPLOYEE)


def test_model_reaches_the_resource_type_named_after_its_schema(httpserver, client):
    """Test that a model reaches the resource type named after its schema, whatever the other resource types."""
    httpserver.expect_request(f"/Users/{USER_ID}").respond_with_json(
        user_payload("User"), content_type="application/scim+json"
    )

    response = client.query(User, USER_ID)

    assert response.user_name == "bjensen@example.com"


@pytest.mark.parametrize("key", ["Employee", "employee", "employee-id", EMPLOYEE])
def test_resource_type_is_designated_by_its_name_its_id_or_itself(
    httpserver, client, key
):
    """Test that a resource type is passed as an object, or by its name or its id, in any case."""
    httpserver.expect_request(f"/Employees/{USER_ID}").respond_with_json(
        user_payload(), content_type="application/scim+json"
    )

    response = client.query(key, USER_ID)

    assert isinstance(response, User)


def test_name_is_preferred_to_the_id(client):
    """Test that a name designates its resource type even when it is the id of another one."""
    client.provider = ScimProvider(
        models=[User],
        resource_types=[
            resource_type("User", "/Users", id="Employee"),
            resource_type("Employee", "/Employees", id="staff"),
        ],
    )

    assert client.resource_endpoint("Employee") == "/Employees"


def test_resource_type_alone_designates_its_model(httpserver, client):
    """Test that a resource type without a model lists the resources it serves."""
    httpserver.expect_request("/Employees").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "Resources": [user_payload()],
        },
        content_type="application/scim+json",
    )

    response = client.query("Employee")

    assert isinstance(response.resources[0], User)


def test_unknown_resource_type_is_refused(client):
    """Test that a resource type the server does not describe is refused."""
    with pytest.raises(InvalidValueException, match="Unknown resource type: 'Pet'"):
        client.query("Pet", USER_ID)

    unknown = resource_type("Pet", "/Pets")
    with pytest.raises(InvalidValueException, match="Unknown resource type: 'Pet'"):
        client.query(unknown, USER_ID)


def test_resource_type_must_serve_the_model(client):
    """Test that a resource type serving another schema is refused."""
    with pytest.raises(InvalidValueException, match="'Employee' does not serve Group"):
        client.create("Employee", Group(display_name="Admins"))


def test_resource_type_must_declare_the_extensions_of_the_model(client):
    """Test that a model carrying an extension its resource type does not declare is refused."""
    client.provider = ScimProvider(
        models=[User, EnterpriseUser],
        resource_types=[ResourceType.from_resource(User), EMPLOYEE],
    )

    with pytest.raises(
        InvalidValueException, match=r"'Employee' does not serve User\[EnterpriseUser\]"
    ):
        client.create("Employee", User[EnterpriseUser](user_name="bjensen"))


def test_resource_type_must_match_the_one_of_the_resource(client):
    """Test that a resource type contradicting the one the resource belongs to is refused."""
    user = User(id=USER_ID, meta=Meta(resource_type="Employee"))

    with pytest.raises(
        InvalidValueException,
        match="belongs to the resource type 'Employee', not 'User'",
    ):
        client.delete("User", user)


def test_resource_type_may_repeat_the_one_of_the_resource(httpserver, client):
    """Test that a resource type agreeing with the one the resource belongs to is accepted."""
    httpserver.expect_request(
        f"/Employees/{USER_ID}", method="DELETE"
    ).respond_with_data(status=204)
    user = User(id=USER_ID, meta=Meta(resource_type="Employee"))

    assert client.delete("employee-id", user) is None


def test_resource_reaches_the_resource_type_it_belongs_to(httpserver, client):
    """Test that a resource read from a server goes back to the resource type of its meta."""
    httpserver.expect_request(f"/Employees/{USER_ID}", method="PUT").respond_with_json(
        user_payload(), content_type="application/scim+json"
    )
    httpserver.expect_request(
        f"/Employees/{USER_ID}", method="PATCH"
    ).respond_with_data(status=204)
    httpserver.expect_request(
        f"/Employees/{USER_ID}", method="DELETE"
    ).respond_with_data(status=204)
    user = User.model_validate(user_payload())
    patch_op = PatchOp[User](
        operations=[
            PatchOperation(
                op=PatchOperation.Op.replace_, path="displayName", value="Babs"
            )
        ]
    )

    assert client.replace(user).id == USER_ID
    assert client.modify(user, patch_op) is None
    assert client.delete(user) is None


def test_unknown_resource_type_of_a_resource_is_refused(client):
    """Test that a resource belonging to an unknown resource type is refused."""
    user = User(id=USER_ID, meta=Meta(resource_type="Pet"))

    with pytest.raises(InvalidValueException, match="Unknown resource type: 'Pet'"):
        client.delete(user)


def test_resource_type_of_a_resource_that_does_not_serve_it_is_refused(make_client):
    """Test that a resource declaring a resource type of another schema is refused."""
    client = make_client(
        ResourceType.from_resource(User),
        resource_type("Member", "/Members", schema=Member.__schema__),
        models=[User, Member],
    )
    user = User(id=USER_ID, meta=Meta(resource_type="Member"))

    with pytest.raises(
        InvalidValueException, match="The resource type 'Member' does not serve User"
    ):
        client.delete(user)


def test_model_with_no_resource_type_named_after_its_schema_is_refused(make_client):
    """Test that a model is not sent to a resource type named otherwise, even if it serves its schema."""
    client = make_client(resource_type("Person", "/People"), models=[User])

    with pytest.raises(InvalidValueException, match="pass the resource type"):
        client.query(User, USER_ID)


def test_resource_type_named_after_another_schema_is_not_used(make_client):
    """Test that a resource type with the right name but another schema is not used."""
    client = make_client(
        ResourceType.from_resource(User),
        resource_type("Member", "/Members", schema=Member.__schema__),
        models=[User, Member],
    )

    with pytest.raises(InvalidValueException, match="pass the resource type"):
        client.resource_endpoint(Member)


def test_model_served_by_no_resource_type_is_refused(make_client):
    """Test that a model no resource type serves is refused."""
    client = make_client(EMPLOYEE, models=[User, Group])

    with pytest.raises(InvalidValueException, match="pass the resource type"):
        client.resource_endpoint(Group)


def test_creation_reaches_the_resource_type(httpserver, client):
    """Test that a resource is created under the resource type passed."""
    httpserver.expect_request("/Employees", method="POST").respond_with_json(
        user_payload(), status=201, content_type="application/scim+json"
    )

    response = client.create("Employee", User(user_name="bjensen@example.com"))

    assert response.id == USER_ID


def test_response_is_read_with_the_extensions_of_the_resource_type(
    httpserver, make_client
):
    """Test that a bare model receives the extensions its resource type declares."""
    client = make_client(
        resource_type("User", "/Users", extensions=[(ENTERPRISE, False)]),
        models=[User, EnterpriseUser],
    )
    httpserver.expect_request("/Users", method="POST").respond_with_json(
        user_payload("User", **{ENTERPRISE: {"employeeNumber": "42"}}),
        status=201,
        content_type="application/scim+json",
    )

    response = client.create(User(user_name="bjensen@example.com"))

    assert response[EnterpriseUser].employee_number == "42"


@pytest.fixture
def requiring_client(make_client):
    """Return a client for a server requiring the enterprise extension on users."""
    return make_client(
        resource_type("User", "/Users", extensions=[(ENTERPRISE, True)]),
        models=[User, EnterpriseUser],
    )


def test_missing_required_extension_is_refused(requiring_client):
    """Test that a resource lacking an extension its resource type requires is not sent."""
    user = User(id=USER_ID, user_name="bjensen@example.com")

    with pytest.raises(
        InvalidValueException, match=f"'User' requires the extension '{ENTERPRISE}'"
    ):
        requiring_client.create(user)

    with pytest.raises(InvalidValueException, match="requires the extension"):
        requiring_client.replace(user)


def test_present_required_extension_is_accepted(httpserver, requiring_client):
    """Test that a resource carrying the extensions its resource type requires is sent."""
    payload = user_payload("User", **{ENTERPRISE: {"employeeNumber": "42"}})
    payload["schemas"].append(ENTERPRISE)
    httpserver.expect_request("/Users", method="POST").respond_with_json(
        payload, status=201, content_type="application/scim+json"
    )
    user = User[EnterpriseUser](user_name="bjensen@example.com")
    user[EnterpriseUser] = EnterpriseUser(employee_number="42")

    response = requiring_client.create(user)

    assert response[EnterpriseUser].employee_number == "42"


def test_search_reaches_the_resource_type(httpserver, client):
    """Test that a search is sent to the endpoint of the resource type passed."""
    httpserver.expect_request("/Employees/.search", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "Resources": [user_payload()],
        },
        content_type="application/scim+json",
    )

    response = client.search("Employee", SearchRequest(filter='userName sw "b"'))

    assert isinstance(response.resources[0], User)


def test_id_and_resource_type_designate_a_resource(httpserver, client):
    """Test that a resource is deleted or modified knowing only its resource type and its id."""
    httpserver.expect_request(
        f"/Employees/{USER_ID}", method="PATCH"
    ).respond_with_json(user_payload(), content_type="application/scim+json")
    httpserver.expect_request(
        f"/Employees/{USER_ID}", method="DELETE"
    ).respond_with_data(status=204)
    patch_op = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "displayName", "value": "Babs"}],
    }

    assert client.modify("Employee", USER_ID, patch_op).id == USER_ID
    assert client.delete("Employee", USER_ID) is None


def test_resource_object_designates_a_resource_under_a_resource_type(
    httpserver, client
):
    """Test that a resource object without meta is reached under the resource type passed."""
    httpserver.expect_request(f"/Employees/{USER_ID}", method="PUT").respond_with_json(
        user_payload(), content_type="application/scim+json"
    )
    httpserver.expect_request(f"/Employees/{USER_ID}").respond_with_json(
        user_payload(), content_type="application/scim+json"
    )
    user = User(id=USER_ID, user_name="bjensen@example.com")

    assert client.replace("Employee", user).id == USER_ID
    assert client.query("Employee", user).id == USER_ID


def test_resource_object_must_be_of_the_model(client):
    """Test that a resource object of another model than the one passed is refused."""
    user = User(id=USER_ID, user_name="bjensen@example.com")

    with pytest.raises(
        InvalidValueException, match="Expected a Group resource, got User"
    ):
        client.query(Group, user)

    with pytest.raises(
        InvalidValueException, match="Expected a Group resource, got User"
    ):
        client.create(Group, user)


def test_payload_is_validated_with_the_model_passed(httpserver, client):
    """Test that a payload is read with the model passed instead of a guessed one."""
    httpserver.expect_request("/Users", method="POST").respond_with_json(
        user_payload("User"), status=201, content_type="application/scim+json"
    )

    response = client.create(User, {"userName": "bjensen@example.com"})

    assert response.id == USER_ID


@pytest.mark.parametrize(
    "arguments,message",
    [
        (("Employee",), "Missing resource"),
        (("Employee", USER_ID), "must be a resource object or a payload"),
        ((User(user_name="a"), User(user_name="b")), "Cannot pass two resources"),
    ],
)
def test_creation_needs_one_resource(client, arguments, message):
    """Test that a creation is refused without exactly one resource to send."""
    with pytest.raises(InvalidValueException, match=message):
        client.create(*arguments)


def test_query_parameters_take_the_place_of_the_id(httpserver, client):
    """Test that query parameters follow a resource object directly."""
    httpserver.expect_request(
        f"/Employees/{USER_ID}", query_string="attributes=userName"
    ).respond_with_json(user_payload(), content_type="application/scim+json")
    user = User.model_validate(user_payload())
    parameters = ResponseParameters(attributes=["userName"])

    assert client.query(user, parameters).id == USER_ID

    with pytest.raises(InvalidValueException, match="query parameters twice"):
        client.query(user, parameters, parameters)


def test_patch_operation_passed_twice_is_refused(client):
    """Test that a patch operation in place of the id cannot be followed by another one."""
    patch_op = PatchOp[User](
        operations=[
            PatchOperation(op=PatchOperation.Op.replace_, path="nickName", value="B")
        ]
    )

    with pytest.raises(InvalidValueException, match="patch operation twice"):
        client.modify(User, patch_op, patch_op)


def test_search_reaches_the_resource_type_of_a_model(httpserver, client):
    """Test that a search under a model is sent to the endpoint of its resource type."""
    httpserver.expect_request("/Users/.search", method="POST").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "Resources": [user_payload("User")],
        },
        content_type="application/scim+json",
    )

    response = client.search(User, SearchRequest(filter='userName sw "b"'))

    assert response.resources[0].id == USER_ID
