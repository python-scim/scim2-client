import pytest
from scim2_models import Error
from scim2_models import Group
from scim2_models import PatchOp
from scim2_models import PatchOperation
from scim2_models import ResourceType
from scim2_models import User

from scim2_client import RequestNetworkError
from scim2_client import RequestPayloadValidationError
from scim2_client import SCIMRequestError


def test_modify_user_200(httpserver, sync_client):
    """Nominal case for a User modification with 200 response (resource returned)."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PATCH"
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "displayName": "Updated Display Name",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
            },
        },
        status=200,
        content_type="application/scim+json",
    )

    operation = PatchOperation(
        op=PatchOperation.Op.replace_, path="displayName", value="Updated Display Name"
    )
    patch_op = PatchOp[User](operations=[operation])

    response = sync_client.modify(
        User, "2819c223-7f76-453a-919d-413861904646", patch_op
    )

    assert isinstance(response, User)
    assert response.id == "2819c223-7f76-453a-919d-413861904646"
    assert response.display_name == "Updated Display Name"


def test_modify_user_204(httpserver, sync_client):
    """Nominal case for a User modification with 204 response (no content)."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PATCH"
    ).respond_with_data(
        "",
        status=204,
        content_type="application/scim+json",
    )

    operation = PatchOperation(
        op=PatchOperation.Op.replace_, path="active", value=False
    )
    patch_op = PatchOp[User](operations=[operation])

    response = sync_client.modify(
        User, "2819c223-7f76-453a-919d-413861904646", patch_op
    )

    assert response is None


def test_modify_user_multiple_operations(httpserver, sync_client):
    """Test User modification with multiple patch operations."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PATCH"
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "displayName": "Betty Jane",
            "active": False,
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff591"',
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
            },
        },
        status=200,
        content_type="application/scim+json",
    )

    operations = [
        PatchOperation(
            op=PatchOperation.Op.replace_, path="displayName", value="Betty Jane"
        ),
        PatchOperation(op=PatchOperation.Op.replace_, path="active", value=False),
    ]
    patch_op = PatchOp[User](operations=operations)

    response = sync_client.modify(
        User, "2819c223-7f76-453a-919d-413861904646", patch_op
    )

    assert isinstance(response, User)
    assert response.display_name == "Betty Jane"
    assert response.active is False


def test_modify_user_add_operation(httpserver, sync_client):
    """Test User modification with add operation."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PATCH"
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "emails": [{"value": "bjensen@example.com", "primary": True}],
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff591"',
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
            },
        },
        status=200,
        content_type="application/scim+json",
    )

    operation = PatchOperation(
        op=PatchOperation.Op.add,
        path="emails",
        value=[{"value": "bjensen@example.com", "primary": True}],
    )
    patch_op = PatchOp[User](operations=[operation])

    response = sync_client.modify(
        User, "2819c223-7f76-453a-919d-413861904646", patch_op
    )

    assert isinstance(response, User)
    assert len(response.emails) == 1
    assert response.emails[0].value == "bjensen@example.com"


def test_modify_user_remove_operation(httpserver, sync_client):
    """Test User modification with remove operation."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PATCH"
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff591"',
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
            },
        },
        status=200,
        content_type="application/scim+json",
    )

    operation = PatchOperation(op=PatchOperation.Op.remove, path="displayName")
    patch_op = PatchOp[User](operations=[operation])

    response = sync_client.modify(
        User, "2819c223-7f76-453a-919d-413861904646", patch_op
    )

    assert isinstance(response, User)
    assert response.display_name is None


def test_modify_group(httpserver, sync_client):
    """Test Group modification."""
    httpserver.expect_request(
        "/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a", method="PATCH"
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": "e9e30dba-f08f-4109-8486-d5c6a331660a",
            "displayName": "Updated Tour Guides",
            "meta": {
                "resourceType": "Group",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff592"',
                "location": "https://example.com/v2/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a",
            },
        },
        status=200,
        content_type="application/scim+json",
    )

    operation = PatchOperation(
        op=PatchOperation.Op.replace_, path="displayName", value="Updated Tour Guides"
    )
    patch_op = PatchOp[Group](operations=[operation])

    response = sync_client.modify(
        Group, "e9e30dba-f08f-4109-8486-d5c6a331660a", patch_op
    )

    assert isinstance(response, Group)
    assert response.display_name == "Updated Tour Guides"


def test_dont_check_response_payload(httpserver, sync_client):
    """Test the check_response_payload attribute."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PATCH"
    ).respond_with_json({"foo": "bar"}, status=200)

    operation = PatchOperation(
        op=PatchOperation.Op.replace_, path="displayName", value="Test"
    )
    patch_op = PatchOp[User](operations=[operation])

    response = sync_client.modify(
        User,
        "2819c223-7f76-453a-919d-413861904646",
        patch_op,
        check_response_payload=False,
    )
    assert response == {"foo": "bar"}


def test_dont_check_request_payload(httpserver, sync_client):
    """Test the check_request_payload attribute."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PATCH"
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "displayName": "Updated Name",
        },
        status=200,
        content_type="application/scim+json",
    )

    patch_op_dict = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "replace", "path": "displayName", "value": "Updated Name"}
        ],
    }

    response = sync_client.modify(
        User,
        "2819c223-7f76-453a-919d-413861904646",
        patch_op_dict,
        check_request_payload=False,
    )
    assert response.id == "2819c223-7f76-453a-919d-413861904646"
    assert response.display_name == "Updated Name"


@pytest.mark.parametrize("code", [400, 401, 403, 404, 409, 412, 500, 501])
def test_errors(httpserver, code, sync_client):
    """Test error cases defined in RFC7644."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PATCH"
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": str(code),
            "detail": f"{code} error",
        },
        status=code,
        content_type="application/scim+json",
    )

    operation = PatchOperation(
        op=PatchOperation.Op.replace_, path="displayName", value="Test"
    )
    patch_op = PatchOp[User](operations=[operation])

    response = sync_client.modify(
        User, "2819c223-7f76-453a-919d-413861904646", patch_op, raise_scim_errors=False
    )

    assert response == Error(
        schemas=["urn:ietf:params:scim:api:messages:2.0:Error"],
        status=code,
        detail=f"{code} error",
    )


def test_invalid_resource_model(httpserver, sync_client):
    """Test that resource_models passed to the method must be part of SCIMClient.resource_models."""
    sync_client.resource_models = (User,)
    sync_client.resource_types = [ResourceType.from_resource(User)]

    operation = PatchOperation(
        op=PatchOperation.Op.replace_, path="displayName", value="Test"
    )
    patch_op = PatchOp[Group](operations=[operation])

    with pytest.raises(SCIMRequestError, match=r"Unknown resource type"):
        sync_client.modify(Group, "some-id", patch_op)


def test_request_validation_error(httpserver, sync_client):
    """Test that incorrect PatchOp creation raises a validation error."""
    # Test with a PatchOp that has invalid data - this should fail during model_dump in prepare_patch_request
    with pytest.raises(
        (RequestPayloadValidationError, ValueError, TypeError),
        match=r"(?i)(validation|invalid|error)",
    ):
        # Create a PatchOp with invalid enum value by bypassing normal validation
        # This will fail when the client tries to serialize it
        from unittest.mock import Mock

        invalid_patch_op = Mock()
        invalid_patch_op.model_dump.side_effect = ValueError("Invalid operation type")
        sync_client.modify(User, "some-id", invalid_patch_op)


def test_request_network_error(httpserver, sync_client):
    """Test that httpx exceptions are transformed in RequestNetworkError."""
    operation = PatchOperation(
        op=PatchOperation.Op.replace_, path="displayName", value="Test"
    )
    patch_op = PatchOp[User](operations=[operation])

    with pytest.raises(
        RequestNetworkError, match="Network error happened during request"
    ):
        sync_client.modify(User, "some-id", patch_op, url="http://invalid.test")


def test_custom_url(httpserver, sync_client):
    """Test modify with custom URL."""
    httpserver.expect_request(
        "/custom/path/users/123", method="PATCH"
    ).respond_with_data(
        "",
        status=204,
        content_type="application/scim+json",
    )

    operation = PatchOperation(
        op=PatchOperation.Op.replace_, path="active", value=False
    )
    patch_op = PatchOp[User](operations=[operation])

    response = sync_client.modify(User, "123", patch_op, url="/custom/path/users/123")

    assert response is None


def test_modify_with_dict_patch_op(httpserver, sync_client):
    """Test modify with dict patch_op."""
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646", method="PATCH"
    ).respond_with_data(
        "",
        status=204,
        content_type="application/scim+json",
    )

    # Use a dict instead of PatchOp object with check_request_payload=True
    patch_op_dict = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "displayName", "value": "Dict Patch"}],
    }

    response = sync_client.modify(
        User,
        "2819c223-7f76-453a-919d-413861904646",
        patch_op_dict,
        check_request_payload=True,
    )

    assert response is None


def test_modify_validation_error(httpserver, sync_client):
    """Test that PatchOp validation errors are handled properly."""
    from unittest.mock import Mock

    from pydantic import ValidationError
    from scim2_models import PatchOp

    # Create a mock PatchOp that raises ValidationError on model_dump
    invalid_patch_op = Mock()

    # Create a proper ValidationError using pytest.raises
    with pytest.raises(ValidationError) as exc_info:
        PatchOp[User](operations="invalid")

    invalid_patch_op.model_dump.side_effect = exc_info.value

    with pytest.raises(
        RequestPayloadValidationError,
        match="Server request payload validation error",
    ):
        sync_client.modify(User, "some-id", invalid_patch_op)
