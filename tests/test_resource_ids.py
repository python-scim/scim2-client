import re

import pytest
from scim2_models import InvalidValueException
from scim2_models import PatchOp
from scim2_models import PatchOperation
from scim2_models import Schema
from scim2_models import User

ANY_PATH = re.compile(".*")


@pytest.fixture
def sync_client(sync_client):
    """Return a client that only looks at the requests it sends."""
    sync_client.check_response_payload = False
    sync_client.check_response_status_codes = False
    return sync_client


def sent_uri(httpserver):
    """Return the request target of the last request, as it went on the wire."""
    request, _ = httpserver.log[-1]
    return request.environ["REQUEST_URI"]


def patch_op():
    return PatchOp[User](
        operations=[
            PatchOperation(
                op=PatchOperation.Op.replace_, path="displayName", value="Bob"
            )
        ]
    )


@pytest.mark.parametrize(
    ("id", "uri"),
    [
        ("42/../../Groups/7", "/Users/42%2F..%2F..%2FGroups%2F7"),
        ("42?attributes=password", "/Users/42%3Fattributes=password"),
        ("42#fragment", "/Users/42%23fragment"),
        ("50%off", "/Users/50%25off"),
        ("été", "/Users/%C3%A9t%C3%A9"),
        ("a:b@c!$&'()*+,;=", "/Users/a:b@c!$&'()*+,;="),
    ],
)
@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda client, id: client.query(User, id), id="query"),
        pytest.param(lambda client, id: client.delete(User, id), id="delete"),
        pytest.param(
            lambda client, id: client.replace(User(id=id, user_name="bob")),
            id="replace",
        ),
        pytest.param(
            lambda client, id: client.modify(User, id, patch_op()), id="modify"
        ),
        pytest.param(
            lambda client, id: client.modify(
                User, id, patch_op().model_dump(), check_request_payload=False
            ),
            id="modify-unchecked",
        ),
    ],
)
def test_id_stays_a_single_path_segment(httpserver, sync_client, call, id, uri):
    """An id cannot reach another resource, another type or the query string."""
    httpserver.expect_request(ANY_PATH).respond_with_data(status=204)

    call(sync_client, id)

    assert sent_uri(httpserver) == uri


def test_schema_urn_is_sent_unencoded(httpserver, sync_client):
    """The URN of a schema keeps its colons, as in the examples of RFC 7644 §4."""
    httpserver.expect_request(ANY_PATH).respond_with_data(status=204)

    sync_client.query(Schema, "urn:ietf:params:scim:schemas:core:2.0:User")

    assert sent_uri(httpserver) == "/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"


def test_id_returned_by_the_server_stays_under_the_endpoint(httpserver, sync_client):
    """A hostile id sent back by the server cannot lead a replace outside of the endpoint."""
    httpserver.expect_request(ANY_PATH).respond_with_data(status=204)
    user = User.model_validate(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "../../tenantB/scim/v2/Users/admin",
            "userName": "bob",
        }
    )

    sync_client.replace(user)

    assert (
        sent_uri(httpserver) == "/Users/..%2F..%2FtenantB%2Fscim%2Fv2%2FUsers%2Fadmin"
    )


@pytest.mark.parametrize("id", [".", ".."])
@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda client, id: client.query(User, id), id="query"),
        pytest.param(lambda client, id: client.delete(User, id), id="delete"),
        pytest.param(
            lambda client, id: client.replace(User(id=id, user_name="bob")),
            id="replace",
        ),
        pytest.param(
            lambda client, id: client.modify(User, id, patch_op()), id="modify"
        ),
    ],
)
def test_dot_segment_id_is_refused(httpserver, sync_client, call, id):
    """URL resolution would drop a dot segment, so the request would target the endpoint."""
    with pytest.raises(InvalidValueException, match="cannot be used as a resource id"):
        call(sync_client, id)

    assert not httpserver.log
