import pytest
from scim2_models import URI
from scim2_models import Context
from scim2_models import ListResponse
from scim2_models import Reference
from scim2_models import ResourceType
from scim2_models import Schema
from scim2_models import ScimProvider
from scim2_models import User
from werkzeug.test import Client as WerkzeugClient

from scim2_client import InvalidServiceDescriptionException
from scim2_client.engines.httpx2 import AsyncClient
from scim2_client.engines.httpx2 import AsyncSCIMClient
from scim2_client.engines.httpx2 import Client
from scim2_client.engines.httpx2 import SyncSCIMClient
from scim2_client.engines.werkzeug import TestSCIMClient

BASE_URL = "https://scim.example.com/tenantA/scim/v2"

FOREIGN_ENDPOINTS = [
    "http://169.254.169.254/latest/meta-data",
    "https://attacker.example/tenantA/scim/v2/Users",
    "https://scim.example.com:8443/tenantA/scim/v2/Users",
    "http://scim.example.com/tenantA/scim/v2/Users",
    "https://scim.example.com/tenantB/scim/v2/Users",
    "https://scim.example.com/tenantA/scim/v2x/Users",
    "/../../tenantB/scim/v2/Users",
    "/Users/../../Groups",
    "/Users?filter=userName pr",
    "/Users#fragment",
    "/Users?",
    "/Users#",
    "/Users\x00",
]

OWN_ENDPOINTS = [
    "/Users",
    "/tenants/A/Users",
    "https://scim.example.com/tenantA/scim/v2/Users",
    "HTTPS://SCIM.EXAMPLE.COM:443/tenantA/scim/v2/Users",
]


def provider(endpoint):
    resource_type = ResourceType.from_resource(User)
    resource_type.endpoint = endpoint and Reference[URI](endpoint)
    return ScimProvider(models=[User], resource_types=[resource_type])


def httpx2_client(endpoint, base_url=BASE_URL):
    return SyncSCIMClient(Client(base_url=base_url), provider=provider(endpoint))


def async_httpx2_client(endpoint):
    return AsyncSCIMClient(AsyncClient(base_url=BASE_URL), provider=provider(endpoint))


def werkzeug_client(endpoint):
    return TestSCIMClient(WerkzeugClient(None), provider=provider(endpoint))


@pytest.mark.parametrize("endpoint", FOREIGN_ENDPOINTS)
@pytest.mark.parametrize("make_client", [httpx2_client, async_httpx2_client])
def test_endpoint_leading_away_from_the_base_url_is_refused(make_client, endpoint):
    """A server cannot send the requests, and their credentials, anywhere but under the base URL."""
    client = make_client(endpoint)

    with pytest.raises(
        InvalidServiceDescriptionException, match="is not under the base URL"
    ):
        client.resource_endpoint(User)


@pytest.mark.parametrize("endpoint", OWN_ENDPOINTS)
@pytest.mark.parametrize("make_client", [httpx2_client, async_httpx2_client])
def test_endpoint_under_the_base_url_is_used(make_client, endpoint):
    """Relative endpoints and absolute ones pointing back to the base URL are both accepted."""
    client = make_client(endpoint)

    assert client.resource_endpoint(User) == endpoint


def test_network_path_reference_stays_under_the_base_url(httpserver):
    """httpx2 drops the host of a '//host/path' endpoint and keeps its path under the base URL."""
    httpserver.expect_request("/scim/v2/Users/1").respond_with_json(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "1",
            "userName": "bob",
        },
        content_type="application/scim+json",
    )
    with Client(base_url=httpserver.url_for("/scim/v2")) as http_client:
        client = SyncSCIMClient(http_client, provider=provider("//evil.example/Users"))
        client.query(User, "1")

    assert [request.path for request, _ in httpserver.log] == ["/scim/v2/Users/1"]


def test_endpoint_is_refused_without_a_base_url():
    """Without a base URL, nothing tells where the requests are allowed to go."""
    client = httpx2_client("/Users", base_url="")

    with pytest.raises(
        InvalidServiceDescriptionException, match="is not under the base URL"
    ):
        client.resource_endpoint(User)


@pytest.mark.parametrize("make_client", [httpx2_client, werkzeug_client])
def test_resource_type_without_endpoint_is_refused(make_client):
    """A resource type the server published without endpoint cannot be requested."""
    client = make_client(None)

    with pytest.raises(
        InvalidServiceDescriptionException, match="A resource type has no endpoint"
    ):
        client.resource_endpoint(User)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost/Users",
        "//localhost/Users",
        "/../Groups",
        "/Users/./x",
        "/Users?x=1",
        "/Users#f",
        "/Users?",
        "/Users#",
    ],
)
def test_werkzeug_engine_only_accepts_relative_paths(endpoint):
    """Without knowing the base URL, only plain relative paths are known to stay under it."""
    client = werkzeug_client(endpoint)

    with pytest.raises(
        InvalidServiceDescriptionException, match="is not under the base URL"
    ):
        client.resource_endpoint(User)


@pytest.mark.parametrize("endpoint", ["/Users", "/tenants/A/Users"])
def test_werkzeug_engine_accepts_relative_paths(endpoint):
    """Relative paths without dot segments are used as they are."""
    client = werkzeug_client(endpoint)

    assert client.resource_endpoint(User) == endpoint


def test_discovered_foreign_endpoint_sends_no_request(httpserver):
    """A hostile endpoint published by the server stops the client before any request leaves."""
    resource_type = ResourceType.from_resource(User)
    resource_type.endpoint = Reference[URI]("http://169.254.169.254/latest/meta-data")
    httpserver.expect_request("/ResourceTypes").respond_with_json(
        ListResponse[ResourceType](
            total_results=1, resources=[resource_type]
        ).model_dump(scim_ctx=Context.RESOURCE_QUERY_RESPONSE),
        content_type="application/scim+json",
    )
    httpserver.expect_request("/Schemas").respond_with_json(
        ListResponse[Schema](total_results=1, resources=[User.to_schema()]).model_dump(
            scim_ctx=Context.RESOURCE_QUERY_RESPONSE
        ),
        content_type="application/scim+json",
    )
    with Client(base_url=httpserver.url_for("/")) as http_client:
        client = SyncSCIMClient(http_client)
        client.discover(service_provider_config=False)

        with pytest.raises(InvalidServiceDescriptionException):
            client.query(User, "123")

    assert {request.path for request, _ in httpserver.log} == {
        "/ResourceTypes",
        "/Schemas",
    }
