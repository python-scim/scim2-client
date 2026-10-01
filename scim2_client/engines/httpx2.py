from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from typing import cast

from httpx2 import AsyncClient
from httpx2 import Client
from httpx2 import InvalidURL
from httpx2 import RequestError
from httpx2 import Response

from scim2_client.client import BaseAsyncSCIMClient
from scim2_client.client import BaseSyncSCIMClient
from scim2_client.client import RawResponse
from scim2_client.errors import RequestNetworkException


def stays_under_base_url(client: Client | AsyncClient, endpoint: str) -> bool:
    """Tell whether the URL httpx2 builds for an endpoint has the origin and the path prefix of the base URL.

    The URL is built as it will be sent, so an absolute endpoint pointing back
    to the base URL is accepted, and the dot segments are already resolved.
    """
    base_url = client.base_url
    if not base_url.is_absolute_url:
        return False

    try:
        url = client.build_request("GET", endpoint).url
    except InvalidURL:
        return False

    return url.origin == base_url.origin and url.raw_path.startswith(base_url.raw_path)


@contextmanager
def handle_request_error() -> Iterator[None]:
    try:
        yield

    except RequestError as exc:
        scim_network_exc = RequestNetworkException()
        scim_network_exc.add_note(str(exc))
        raise scim_network_exc from exc


class SyncSCIMClient(BaseSyncSCIMClient):
    """Perform SCIM requests over the network and validate responses.

    :param client: A :class:`httpx2.Client` instance that will be used to send requests.
    :param provider: The :class:`~scim2_models.ScimProvider` describing the server.
        If a request payload describe a resource it does not know, an exception will be raised.
        The :class:`~scim2_models.ScimPolicy` it carries rules how much the payloads
        exchanged with the server may depart from the specification.
    :param resource_models: Deprecated, pass a :paramref:`provider` instead.
    :param check_request_payload: If :data:`False`,
        :code:`resource` is expected to be a dict that will be passed as-is in the request.
        This value can be overwritten in methods.
    :param check_response_payload: Whether to validate that the response payloads are valid.
        If set, the raw payload will be returned. This value can be overwritten in methods.
    :param raise_scim_errors: If :data:`True` and the server returned an
        :class:`~scim2_models.Error` object during a request, a :class:`~scim2_models.SCIMException`
        exception will be raised. If :data:`False` the error object is returned. This value can be overwritten in methods.
    """

    def __init__(self, client: Client, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.client = client

    def _stays_under_base_url(self, endpoint: str) -> bool:
        return stays_under_base_url(self.client, endpoint)

    def _parse_json(self, response: RawResponse) -> Any:
        return cast(Response, response).json()

    def request(self, method: str, url: str, **kwargs: Any) -> Response:
        with handle_request_error():
            return self.client.request(method, url, **kwargs)


class AsyncSCIMClient(BaseAsyncSCIMClient):
    """Perform SCIM requests over the network and validate responses.

    :param client: A :class:`httpx2.AsyncClient` instance that will be used to send requests.
    :param provider: The :class:`~scim2_models.ScimProvider` describing the server.
        If a request payload describe a resource it does not know, an exception will be raised.
        The :class:`~scim2_models.ScimPolicy` it carries rules how much the payloads
        exchanged with the server may depart from the specification.
    :param resource_models: Deprecated, pass a :paramref:`provider` instead.
    :param check_request_payload: If :data:`False`,
        :code:`resource` is expected to be a dict that will be passed as-is in the request.
        This value can be overwritten in methods.
    :param check_response_payload: Whether to validate that the response payloads are valid.
        If set, the raw payload will be returned. This value can be overwritten in methods.
    :param raise_scim_errors: If :data:`True` and the server returned an
        :class:`~scim2_models.Error` object during a request, a :class:`~scim2_models.SCIMException`
        exception will be raised. If :data:`False` the error object is returned. This value can be overwritten in methods.

    """

    def __init__(self, client: AsyncClient, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.client = client

    def _stays_under_base_url(self, endpoint: str) -> bool:
        return stays_under_base_url(self.client, endpoint)

    def _parse_json(self, response: RawResponse) -> Any:
        return cast(Response, response).json()

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:
        with handle_request_error():
            return await self.client.request(method, url, **kwargs)
