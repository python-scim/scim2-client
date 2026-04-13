import datetime

import pytest
from scim2_models import Error
from scim2_models import Group
from scim2_models import ListResponse
from scim2_models import Meta
from scim2_models import Resource
from scim2_models import ResourceType
from scim2_models import ResponseParameters
from scim2_models import SearchRequest
from scim2_models import ServiceProviderConfig
from scim2_models import User
from scim2_models.resources.service_provider_config import ETag

from scim2_client import SCIMRequestError
from scim2_client.errors import RequestNetworkError
from scim2_client.errors import ResponsePayloadValidationError
from scim2_client.errors import SCIMClientError
from scim2_client.errors import SCIMResponseError
from scim2_client.errors import SCIMResponseErrorObject
from scim2_client.errors import UnexpectedContentFormat
from scim2_client.errors import UnexpectedContentType
from scim2_client.errors import UnexpectedStatusCode


@pytest.fixture
def httpserver(httpserver):
    httpserver.expect_request(
        "/Users/2819c223-7f76-453a-919d-413861904646"
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
            },
        },
        status=200,
    )

    httpserver.expect_request("/Users/unknown").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "Resource unknown not found",
            "status": "404",
        },
        status=404,
    )

    httpserver.expect_request("/Users/bad-request").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "Bad request",
            "status": "400",
        },
        status=400,
    )

    httpserver.expect_request("/Users/conflict").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "scimType": "uniqueness",
            "detail": "User already exists",
            "status": "409",
        },
        status=409,
    )

    httpserver.expect_request("/Users/no-detail").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "500",
        },
        status=500,
    )

    httpserver.expect_request("/Users/status-201").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
            },
        },
        status=201,
    )

    httpserver.expect_request("/Users/not-json").respond_with_data(
        "foobar", status=200, content_type="application/scim+json"
    )

    httpserver.expect_request("/Users/not-a-scim-object").respond_with_json(
        {"foo": "bar"}, status=200, content_type="application/scim+json"
    )

    httpserver.expect_request("/Users/content-type-with-charset").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
            },
        },
        status=200,
        content_type="application/scim+json; charset=utf-8",
    )

    httpserver.expect_request("/Users/bad-content-type").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "2819c223-7f76-453a-919d-413861904646",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
            },
        },
        status=200,
        content_type="application/text",
    )

    httpserver.expect_request("/Users/its-a-group").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": "e9e30dba-f08f-4109-8486-d5c6a331660a",
            "displayName": "Tour Guides",
            "members": [
                {
                    "value": "2819c223-7f76-453a-919d-413861904646",
                    "$ref": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
                    "display": "Babs Jensen",
                },
            ],
            "meta": {
                "resourceType": "Group",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff592"',
                "location": "https://example.com/v2/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a",
            },
        },
        status=200,
    )

    httpserver.expect_request("/Users").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 2,
            "Resources": [
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "id": "2819c223-7f76-453a-919d-413861904646",
                    "userName": "bjensen@example.com",
                    "meta": {
                        "resourceType": "User",
                        "created": "2010-01-23T04:56:22Z",
                        "lastModified": "2011-05-13T04:42:34Z",
                        "version": 'W\\/"3694e05e9dff590"',
                        "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
                    },
                },
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "id": "074860c7-70e9-4db5-ad40-a32bab8be11d",
                    "userName": "jsmith@example.com",
                    "meta": {
                        "resourceType": "User",
                        "created": "2010-02-23T04:56:22Z",
                        "lastModified": "2011-06-13T04:42:34Z",
                        "version": 'W\\/"deadbeef0000"',
                        "location": "https://example.com/v2/Users/074860c7-70e9-4db5-ad40-a32bab8be11d",
                    },
                },
            ],
        },
        status=200,
    )

    httpserver.expect_request("/Groups").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 0,
        },
        status=200,
    )

    httpserver.expect_request("/Foobars").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "Invalid Resource",
            "status": "404",
        },
        status=404,
    )

    httpserver.expect_request("/").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 2,
            "Resources": [
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "id": "2819c223-7f76-453a-919d-413861904646",
                    "userName": "bjensen@example.com",
                    "meta": {
                        "resourceType": "User",
                        "created": "2010-01-23T04:56:22Z",
                        "lastModified": "2011-05-13T04:42:34Z",
                        "version": 'W\\/"3694e05e9dff590"',
                        "location": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
                    },
                },
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                    "id": "e9e30dba-f08f-4109-8486-d5c6a331660a",
                    "displayName": "Tour Guides",
                    "members": [
                        {
                            "value": "2819c223-7f76-453a-919d-413861904646",
                            "$ref": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
                            "display": "Babs Jensen",
                        },
                    ],
                    "meta": {
                        "resourceType": "Group",
                        "created": "2010-01-23T04:56:22Z",
                        "lastModified": "2011-05-13T04:42:34Z",
                        "version": 'W\\/"3694e05e9dff592"',
                        "location": "https://example.com/v2/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a",
                    },
                },
            ],
        },
        status=200,
    )

    httpserver.expect_request("/ServiceProviderConfig").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "http://example.com/help/scim.html",
            "patch": {"supported": True},
            "bulk": {
                "supported": True,
                "maxOperations": 1000,
                "maxPayloadSize": 1048576,
            },
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": True},
            "sort": {"supported": True},
            "etag": {"supported": True},
            "authenticationSchemes": [
                {
                    "name": "OAuth Bearer Token",
                    "description": "Authentication scheme using the OAuth Bearer Token Standard",
                    "specUri": "http://www.rfc-editor.org/info/rfc6750",
                    "documentationUri": "http://example.com/help/oauth.html",
                    "type": "oauthbearertoken",
                    "primary": True,
                },
                {
                    "name": "HTTP Basic",
                    "description": "Authentication scheme using the HTTP Basic Standard",
                    "specUri": "http://www.rfc-editor.org/info/rfc2617",
                    "documentationUri": "http://example.com/help/httpBasic.html",
                    "type": "httpbasic",
                },
            ],
            "meta": {
                "location": "https://example.com/v2/ServiceProviderConfig",
                "resourceType": "ServiceProviderConfig",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff594"',
            },
        }
    )
    return httpserver


def test_user_with_valid_id(sync_client):
    """Test that querying an existing user with an id correctly instantiate an User object."""
    response = sync_client.query(
        User(id="2819c223-7f76-453a-919d-413861904646"), raise_scim_errors=False
    )
    assert response == User(
        id="2819c223-7f76-453a-919d-413861904646",
        user_name="bjensen@example.com",
        meta=Meta(
            resource_type="User",
            created=datetime.datetime(
                2010, 1, 23, 4, 56, 22, tzinfo=datetime.timezone.utc
            ),
            last_modified=datetime.datetime(
                2011, 5, 13, 4, 42, 34, tzinfo=datetime.timezone.utc
            ),
            version='W\\/"3694e05e9dff590"',
            location="https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
        ),
    )


def test_user_with_invalid_id(sync_client):
    """Test that querying an user with an invalid id instantiate an Error object."""
    response = sync_client.query(User(id="unknown"), raise_scim_errors=False)
    assert response == Error(detail="Resource unknown not found", status=404)


def test_raise_scim_errors(sync_client):
    """Test that querying an user with an invalid id raises an exception."""
    with pytest.raises(
        SCIMResponseErrorObject,
        match="Resource unknown not found",
    ) as exc_info:
        sync_client.query(User(id="unknown"), raise_scim_errors=True)

    assert exc_info.value.to_error() == Error(
        detail="Resource unknown not found", status=404
    )


def test_raise_scim_errors_with_scim_type(sync_client):
    """Test that the exception message includes scim_type when present."""
    with pytest.raises(
        SCIMResponseErrorObject,
        match="uniqueness: User already exists",
    ) as exc_info:
        sync_client.query(User(id="conflict"), raise_scim_errors=True)

    assert exc_info.value.to_error() == Error(
        detail="User already exists", status=409, scim_type="uniqueness"
    )


def test_raise_scim_errors_without_detail(sync_client):
    """Test that the exception works when the error has no detail."""
    with pytest.raises(
        SCIMResponseErrorObject,
        match="SCIM Error",
    ) as exc_info:
        sync_client.query(User(id="no-detail"), raise_scim_errors=True)

    assert exc_info.value.to_error() == Error(status=500)


def test_all_users(sync_client):
    """Test that querying all existing users instantiate a ListResponse object."""
    response = sync_client.query(User)
    assert response == ListResponse[User](
        total_results=2,
        resources=[
            User(
                id="2819c223-7f76-453a-919d-413861904646",
                user_name="bjensen@example.com",
                meta=Meta(
                    resource_type="User",
                    created=datetime.datetime(
                        2010, 1, 23, 4, 56, 22, tzinfo=datetime.timezone.utc
                    ),
                    last_modified=datetime.datetime(
                        2011, 5, 13, 4, 42, 34, tzinfo=datetime.timezone.utc
                    ),
                    version='W\\/"3694e05e9dff590"',
                    location="https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
                ),
            ),
            User(
                id="074860c7-70e9-4db5-ad40-a32bab8be11d",
                user_name="jsmith@example.com",
                meta=Meta(
                    resource_type="User",
                    created=datetime.datetime(
                        2010, 2, 23, 4, 56, 22, tzinfo=datetime.timezone.utc
                    ),
                    last_modified=datetime.datetime(
                        2011, 6, 13, 4, 42, 34, tzinfo=datetime.timezone.utc
                    ),
                    version='W\\/"deadbeef0000"',
                    location="https://example.com/v2/Users/074860c7-70e9-4db5-ad40-a32bab8be11d",
                ),
            ),
        ],
    )


def test_custom_url(sync_client):
    """Test that querying by passing the 'url' parameter directly to httpx is accepted."""
    response = sync_client.query(url="/Users/2819c223-7f76-453a-919d-413861904646")
    assert response == User(
        id="2819c223-7f76-453a-919d-413861904646",
        user_name="bjensen@example.com",
        meta=Meta(
            resource_type="User",
            created=datetime.datetime(
                2010, 1, 23, 4, 56, 22, tzinfo=datetime.timezone.utc
            ),
            last_modified=datetime.datetime(
                2011, 5, 13, 4, 42, 34, tzinfo=datetime.timezone.utc
            ),
            version='W\\/"3694e05e9dff590"',
            location="https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
        ),
    )


def test_no_result(sync_client):
    """Test querying a resource with no object."""
    response = sync_client.query(Group)
    assert response == ListResponse[Group](total_results=0, resources=None)


def test_bad_request(sync_client):
    """Test querying a resource unknown from the server instantiate an Error object."""
    response = sync_client.query(User(id="bad-request"), raise_scim_errors=False)
    assert response == Error(status=400, detail="Bad request")


def test_resource_unknown_by_server(sync_client):
    """Test querying a resource unknown from the server instantiate an Error object."""

    class Foobar(Resource):
        __schema__ = "urn:ietf:params:scim:schemas:core:2.0:Foobar"

    sync_client.resource_models = (*sync_client.resource_models, Foobar)
    sync_client.resource_types = [
        *sync_client.resource_types,
        ResourceType.from_resource(Foobar),
    ]
    response = sync_client.query(Foobar, raise_scim_errors=False)
    assert response == Error(status=404, detail="Invalid Resource")


def test_bad_resource_model(sync_client):
    """Test querying a resource unknown from the client raise a SCIMResponseError."""
    sync_client.resource_models = (User,)
    sync_client.resource_types = [ResourceType.from_resource(User)]

    with pytest.raises(
        SCIMResponseError,
        match="Expected type User but got unknown resource with schemas: urn:ietf:params:scim:schemas:core:2.0:Group",
    ):
        sync_client.query(User(id="its-a-group"))


def test_all(sync_client):
    """Test querying all resources from the server instation a ListResponse object."""
    response = sync_client.query()
    assert isinstance(response, ListResponse)
    assert response.total_results == 2
    user, group = response.resources
    assert isinstance(user, User)
    assert isinstance(group, Group)


def test_all_unexpected_type(sync_client):
    """Test retrieving a payload for an object which type has not been passed in parameters raise a ResponsePayloadValidationError."""
    sync_client.resource_models = (User,)
    sync_client.resource_types = [ResourceType.from_resource(User)]

    with pytest.raises(
        ResponsePayloadValidationError, match="Server response payload validation error"
    ):
        sync_client.query()


def test_response_is_not_json(sync_client):
    """Test situations where servers return an invalid JSON object."""
    with pytest.raises(UnexpectedContentFormat):
        sync_client.query(User(id="not-json"))


def test_not_a_scim_object(sync_client):
    """Test retrieving a valid JSON object without a schema."""
    with pytest.raises(
        SCIMResponseError,
        match="Expected type User but got undefined object with no schema",
    ):
        sync_client.query(User(id="not-a-scim-object"))


def test_dont_check_response_payload(sync_client):
    """Test the check_response_payload attribute."""
    response = sync_client.query(
        User(id="not-a-scim-object"), check_response_payload=False
    )
    assert response == {"foo": "bar"}


def test_response_bad_status_code(sync_client):
    """Test situations where servers return an invalid status code."""
    with pytest.raises(UnexpectedStatusCode):
        sync_client.query(User(id="status-201"))
    sync_client.query(User(id="status-201"), expected_status_codes=None)


def test_response_content_type_with_charset(sync_client):
    """Test situations where servers return a valid content-type with a charset information."""
    user = sync_client.query(User(id="content-type-with-charset"))
    assert isinstance(user, User)


def test_response_bad_content_type(sync_client):
    """Test situations where servers return an invalid content-type response."""
    with pytest.raises(UnexpectedContentType):
        sync_client.query(User(id="bad-content-type"))


def test_search_request(httpserver, sync_client):
    query_string = "attributes=userName&attributes=displayName&filter=userName+Eq+%22john%22&sortBy=userName&sortOrder=ascending&startIndex=1&count=10"

    httpserver.expect_request(
        "/Users/with-qs", query_string=query_string
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "with-qs",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/with-qs",
            },
        },
        status=200,
    )
    req = SearchRequest(
        attributes=["userName", "displayName"],
        filter='userName Eq "john"',
        sort_by="userName",
        sort_order=SearchRequest.SortOrder.ascending,
        start_index=1,
        count=10,
    )

    response = sync_client.query(User(id="with-qs"), req)
    assert isinstance(response, User)
    assert response.id == "with-qs"


def test_query_parameters(httpserver, sync_client):
    """ResponseParameters can be used instead of SearchRequest for single-resource queries."""
    query_string = "attributes=userName&attributes=displayName"

    httpserver.expect_request(
        "/Users/with-rp", query_string=query_string
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "with-rp",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/with-rp",
            },
        },
        status=200,
    )
    params = ResponseParameters(attributes=["userName", "displayName"])
    response = sync_client.query(User(id="with-rp"), params)
    assert isinstance(response, User)
    assert response.id == "with-rp"


def test_query_dont_check_request_payload(httpserver, sync_client):
    """Raw dict payloads are forwarded as-is when check_request_payload is False."""
    query_string = "attributes=userName&attributes=displayName&excluded_attributes=timezone&excluded_attributes=phoneNumbers&filter=userName+Eq+%22john%22&sort_by=userName&sort_order=ascending&start_index=1&count=10"

    httpserver.expect_request(
        "/Users/with-qs", query_string=query_string
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "with-qs",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/with-qs",
            },
        },
        status=200,
    )
    req = {
        "attributes": ["userName", "displayName"],
        "excluded_attributes": ["timezone", "phoneNumbers"],
        "filter": 'userName Eq "john"',
        "sort_by": "userName",
        "sort_order": SearchRequest.SortOrder.ascending.value,
        "start_index": 1,
        "count": 10,
    }

    response = sync_client.query(User(id="with-qs"), req, check_request_payload=False)
    assert isinstance(response, User)
    assert response.id == "with-qs"


def test_deprecated_search_request_keyword(httpserver, sync_client):
    """Passing search_request as keyword argument emits a DeprecationWarning."""
    query_string = "attributes=userName"

    httpserver.expect_request(
        "/Users/with-dep", query_string=query_string
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "with-dep",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W\\/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/with-dep",
            },
        },
        status=200,
    )
    params = ResponseParameters(attributes=["userName"])
    with pytest.warns(DeprecationWarning, match="search_request.*deprecated"):
        response = sync_client.query(User(id="with-dep"), search_request=params)
    assert isinstance(response, User)
    assert response.id == "with-dep"


def test_both_search_request_and_query_parameters_raises(sync_client):
    """Passing both search_request and query_parameters raises TypeError."""
    params = ResponseParameters(attributes=["userName"])
    with pytest.raises(TypeError, match="Cannot pass both"):
        sync_client.query(User(id="some-id"), params, search_request=params)


def test_invalid_resource_model(sync_client):
    """Test that resource_models passed to the method must be part of SCIMClient.resource_models."""
    sync_client.resource_models = (User,)
    sync_client.resource_types = [ResourceType.from_resource(User)]

    with pytest.raises(SCIMRequestError, match=r"Unknown resource type"):
        sync_client.query(Group)


def test_service_provider_config_endpoint(sync_client):
    """Test that querying the /ServiceProviderConfig enpdoint correctly returns a ServiceProviderConfig (and not a ListResponse)."""
    response = sync_client.query(ServiceProviderConfig)
    assert isinstance(response, ServiceProviderConfig)


def test_service_provider_config_endpoint_with_an_id(sync_client):
    """Test that querying the /ServiceProviderConfig with an id raise an exception."""
    with pytest.raises(
        SCIMClientError, match="ServiceProviderConfig cannot have an id"
    ):
        spc = ServiceProviderConfig()
        spc.id = "dummy"
        sync_client.query(spc)


def test_request_network_error(sync_client):
    """Test that httpx exceptions are transformed in RequestNetworkError."""
    with pytest.raises(
        RequestNetworkError, match="Network error happened during request"
    ):
        sync_client.query(url="http://invalid.test")


def test_query_sends_if_none_match(httpserver, sync_client):
    """If-None-Match is sent when querying a resource instance with ETag support."""
    sync_client.service_provider_config = ServiceProviderConfig(
        etag=ETag(supported=True)
    )
    user = User(
        id="etag-304-user",
        user_name="bjensen@example.com",
        meta=Meta(version='W/"3694e05e9dff590"'),
    )

    httpserver.expect_request(
        "/Users/etag-304-user",
        headers={"If-None-Match": 'W/"3694e05e9dff590"'},
    ).respond_with_data(status=304)

    response = sync_client.query(user)
    assert response is user


def test_query_returns_fresh_resource_on_200(httpserver, sync_client):
    """Server returns 200 with updated resource when ETag does not match."""
    sync_client.service_provider_config = ServiceProviderConfig(
        etag=ETag(supported=True)
    )
    user = User(
        id="etag-200-user",
        user_name="bjensen@example.com",
        meta=Meta(version='W/"old-version"'),
    )

    httpserver.expect_request(
        "/Users/etag-200-user",
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "etag-200-user",
            "userName": "bjensen@example.com",
            "displayName": "Updated Name",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W/"new-version"',
                "location": "https://example.com/v2/Users/etag-200-user",
            },
        },
        status=200,
    )

    response = sync_client.query(user)
    assert response is not user
    assert response.display_name == "Updated Name"


def test_query_no_if_none_match_without_version(httpserver, sync_client):
    """No If-None-Match header when the resource has no meta.version."""
    sync_client.service_provider_config = ServiceProviderConfig(
        etag=ETag(supported=True)
    )

    httpserver.expect_request(
        "/Users/etag-no-version",
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "etag-no-version",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "location": "https://example.com/v2/Users/etag-no-version",
            },
        },
        status=200,
    )

    user = User(id="etag-no-version")
    response = sync_client.query(user)
    assert isinstance(response, User)


def test_query_no_if_none_match_without_etag_support(httpserver, sync_client):
    """No If-None-Match header when the server does not support ETags."""
    httpserver.expect_request(
        "/Users/etag-unsupported",
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "etag-unsupported",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/etag-unsupported",
            },
        },
        status=200,
    )

    user = User(
        id="etag-unsupported",
        meta=Meta(version='W/"3694e05e9dff590"'),
    )
    response = sync_client.query(user)
    assert isinstance(response, User)


def test_query_no_if_none_match_with_query_parameters(httpserver, sync_client):
    """No If-None-Match header when query_parameters are present."""
    sync_client.service_provider_config = ServiceProviderConfig(
        etag=ETag(supported=True)
    )

    httpserver.expect_request(
        "/Users/etag-with-params",
    ).respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "etag-with-params",
            "userName": "bjensen@example.com",
            "meta": {
                "resourceType": "User",
                "created": "2010-01-23T04:56:22Z",
                "lastModified": "2011-05-13T04:42:34Z",
                "version": 'W/"3694e05e9dff590"',
                "location": "https://example.com/v2/Users/etag-with-params",
            },
        },
        status=200,
    )

    user = User(
        id="etag-with-params",
        meta=Meta(version='W/"3694e05e9dff590"'),
    )
    params = ResponseParameters(attributes=["userName"])
    response = sync_client.query(user, params)
    assert isinstance(response, User)
