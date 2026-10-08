import pytest
from scim2_models import Error
from scim2_models import ETag
from scim2_models import Group
from scim2_models import InvalidValueException
from scim2_models import ResponseParameters
from scim2_models import ScimProvider
from scim2_models import SearchRequest
from scim2_models import ServiceProviderConfig
from scim2_models import User

from scim2_client import Me

USER_ID = "2819c223-7f76-453a-919d-413861904646"
USER_PAYLOAD = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "id": USER_ID,
    "userName": "bjensen@example.com",
    "meta": {
        "resourceType": "User",
        "location": f"https://example.com/v2/Users/{USER_ID}",
    },
}
GROUP_PAYLOAD = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "id": "e9e30dba-f08f-4109-8486-d5c6a331660a",
    "displayName": "Tour Guides",
}
LOCATION = {"Location": f"https://example.com/v2/Users/{USER_ID}"}


def respond(httpserver, method, payload, status=200, **kwargs):
    httpserver.expect_request("/Me", method=method, **kwargs).respond_with_json(
        payload, status=status, headers=LOCATION, content_type="application/scim+json"
    )


def test_query_reads_the_resource_of_the_authenticated_client(httpserver, sync_client):
    """Me reads the resource of the authenticated client under /Me."""
    respond(httpserver, "GET", USER_PAYLOAD)

    response = sync_client.query(Me)

    assert isinstance(response, User)
    assert response.id == USER_ID


def test_query_reads_a_resource_of_any_served_type(httpserver, sync_client):
    """The resource under /Me may be of any resource type the server serves."""
    respond(httpserver, "GET", GROUP_PAYLOAD)

    assert isinstance(sync_client.query(Me), Group)


def test_query_sends_the_query_parameters(httpserver, sync_client):
    """The query parameters directly follow Me."""
    respond(
        httpserver,
        "GET",
        USER_PAYLOAD,
        query_string={"attributes": "userName,displayName"},
    )

    parameters = ResponseParameters(attributes=["userName", "displayName"])
    assert isinstance(sync_client.query(Me, parameters), User)


def test_query_returns_the_error_of_a_server_without_me(httpserver, sync_client):
    """A server that does not support /Me answers 501 (RFC 7644 §3.11)."""
    respond(
        httpserver,
        "GET",
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "501",
            "detail": "/Me is not supported",
        },
        status=501,
    )

    response = sync_client.query(Me, raise_scim_errors=False)

    assert isinstance(response, Error)
    assert response.status == 501


@pytest.mark.parametrize("id", [USER_ID, User(id=USER_ID)])
def test_query_refuses_an_id(sync_client, id):
    """Me already designates a single resource, so it takes no id."""
    with pytest.raises(InvalidValueException, match="Cannot pass an id with Me"):
        sync_client.query(Me, id)


def test_create_posts_under_me(httpserver, sync_client):
    """A creation under Me sends the checked payload to /Me."""
    respond(
        httpserver,
        "POST",
        USER_PAYLOAD,
        status=201,
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "bjensen@example.com",
        },
    )

    response = sync_client.create(Me, User(user_name="bjensen@example.com"))

    assert isinstance(response, User)
    assert response.id == USER_ID


def test_create_accepts_a_resource_of_another_type(httpserver, sync_client):
    """The server chooses the resource type of a creation under /Me."""
    respond(httpserver, "POST", GROUP_PAYLOAD, status=201)

    response = sync_client.create(Me, User(user_name="bjensen@example.com"))

    assert isinstance(response, Group)


def test_create_without_payload_check_posts_under_me(httpserver, sync_client):
    """An unchecked payload is sent to /Me with no url passed."""
    payload = {"userName": "bjensen@example.com"}
    respond(httpserver, "POST", USER_PAYLOAD, status=201, json=payload)

    response = sync_client.create(
        Me, payload, check_request_payload=False, check_response_payload=False
    )

    assert response == USER_PAYLOAD


def test_create_requires_a_resource(sync_client):
    """A creation under Me needs the resource to create."""
    with pytest.raises(InvalidValueException, match="Missing resource"):
        sync_client.create(Me)


def test_replace_puts_under_me(httpserver, sync_client):
    """A replacement under Me sends the resource to /Me."""
    respond(httpserver, "PUT", USER_PAYLOAD)

    user = User(id=USER_ID, user_name="bjensen@example.com")
    response = sync_client.replace(Me, user)

    assert isinstance(response, User)
    assert response.id == USER_ID


def test_replace_sends_if_match(httpserver, sync_client):
    """A replacement under Me is conditional upon the version of the resource."""
    sync_client.provider = ScimProvider(
        models=sync_client.provider.models,
        config=ServiceProviderConfig(etag=ETag(supported=True)),
    )
    respond(httpserver, "PUT", USER_PAYLOAD, headers={"If-Match": 'W/"1"'})

    user = User.model_validate({**USER_PAYLOAD, "meta": {"version": 'W/"1"'}})

    assert isinstance(sync_client.replace(Me, user), User)


def test_replace_needs_no_id(httpserver, sync_client):
    """/Me designates the resource, so the replacing resource may have no id."""
    respond(
        httpserver,
        "PUT",
        USER_PAYLOAD,
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "bjensen@example.com",
        },
    )

    response = sync_client.replace(Me, User(user_name="bjensen@example.com"))

    assert isinstance(response, User)
    assert response.id == USER_ID


def test_replace_without_payload_check_puts_under_me(httpserver, sync_client):
    """An unchecked payload is sent to /Me with no url passed."""
    respond(httpserver, "PUT", USER_PAYLOAD, json=USER_PAYLOAD)

    response = sync_client.replace(
        Me, USER_PAYLOAD, check_request_payload=False, check_response_payload=False
    )

    assert response == USER_PAYLOAD


def test_modify_patches_under_me(httpserver, sync_client, patch_op):
    """A modification under Me sends the patch operation to /Me."""
    respond(
        httpserver,
        "PATCH",
        USER_PAYLOAD,
        json=patch_op.model_dump(),
    )

    response = sync_client.modify(Me, patch_op)

    assert isinstance(response, User)
    assert response.id == USER_ID


def test_modify_without_content(httpserver, sync_client, patch_op):
    """A modification under Me may be answered without content."""
    httpserver.expect_request("/Me", method="PATCH").respond_with_data(status=204)

    assert sync_client.modify(Me, patch_op) is None


def test_modify_refuses_an_id(sync_client, patch_op):
    """Me already designates a single resource, so it takes no id."""
    with pytest.raises(InvalidValueException, match="Cannot pass an id with Me"):
        sync_client.modify(Me, USER_ID, patch_op)


def test_modify_requires_a_patch_operation(sync_client):
    """A modification under Me needs a patch operation."""
    with pytest.raises(InvalidValueException, match="Missing patch operation"):
        sync_client.modify(Me)


def test_delete_deletes_under_me(httpserver, sync_client):
    """A deletion under Me sends a DELETE to /Me."""
    httpserver.expect_request("/Me", method="DELETE").respond_with_data(status=204)

    assert sync_client.delete(Me) is None


def test_delete_refuses_an_id(sync_client):
    """Me already designates a single resource, so it takes no id."""
    with pytest.raises(InvalidValueException, match="Cannot pass an id with Me"):
        sync_client.delete(Me, USER_ID)


def test_url_wins_over_me(httpserver, sync_client):
    """A url passed explicitly is used instead of /Me."""
    httpserver.expect_request(f"/Users/{USER_ID}").respond_with_json(
        USER_PAYLOAD, content_type="application/scim+json"
    )

    assert isinstance(sync_client.query(Me, url=f"/Users/{USER_ID}"), User)


def test_search_is_refused(sync_client):
    """RFC 7644 defines no search under /Me."""
    with pytest.raises(InvalidValueException, match="Cannot search under /Me"):
        sync_client.search(Me, SearchRequest())


def test_resource_endpoint(sync_client):
    """The endpoint of Me is /Me."""
    assert sync_client.resource_endpoint(Me) == "/Me"


def test_representation():
    """Me reads as its name."""
    assert repr(Me) == "Me"
