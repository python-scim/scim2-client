from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from typing import TypeVar
from typing import cast

from httpx2 import AsyncClient
from httpx2 import Client
from httpx2 import InvalidURL
from httpx2 import RequestError
from httpx2 import Response
from scim2_models import AnyResource
from scim2_models import BulkRequest
from scim2_models import BulkResponse
from scim2_models import Context
from scim2_models import Error
from scim2_models import ListResponse
from scim2_models import PatchOp
from scim2_models import Resource
from scim2_models import ResponseParameters
from scim2_models import SCIMException
from scim2_models import SearchRequest

from scim2_client.client import BaseAsyncSCIMClient
from scim2_client.client import BaseSyncSCIMClient
from scim2_client.errors import RequestNetworkException
from scim2_client.errors import SCIMClientException
from scim2_client.errors import UnexpectedContentFormatException

ResourceT = TypeVar("ResourceT", bound=Resource[Any])


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
def handle_request_error(payload: object = None) -> Iterator[None]:
    try:
        yield

    except RequestError as exc:
        scim_network_exc = RequestNetworkException(source=payload)
        scim_network_exc.add_note(str(exc))
        raise scim_network_exc from exc


def decode_payload(response: Response) -> Any:
    """Decode the JSON body of a response, or return None when it has no body.

    A body too deeply nested for the decoder, or holding an integer too long for
    Python to convert, is reported as any other body that is not valid JSON.
    """
    try:
        return response.json() if response.text else None
    except (ValueError, RecursionError) as exc:
        raise UnexpectedContentFormatException(source=response) from exc


@contextmanager
def handle_response_error(response: Response) -> Iterator[None]:
    try:
        yield

    except (SCIMClientException, SCIMException) as exc:
        # SCIMException comes from scim2-models and has no 'source' attribute.
        exc.source = response  # type: ignore[union-attr]
        raise exc


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

    def create(
        self,
        resource: AnyResource | dict[str, Any],
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.CREATION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> AnyResource | Error | dict[str, Any]:
        req = self._prepare_create_request(
            resource=resource,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = self.client.post(req.url, json=req.payload, **req.request_kwargs)

        with handle_response_error(response):
            return cast(
                "AnyResource | Error | dict[str, Any]",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=req.expected_status_codes,
                    expected_types=req.expected_types,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                    scim_ctx=Context.RESOURCE_CREATION_RESPONSE,
                ),
            )

    def query(
        self,
        target: type[Resource[Any]] | Resource[Any] | None = None,
        id: str | None = None,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.QUERY_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> Resource[Any] | ListResponse[Resource[Any]] | Error | dict[str, Any]:
        req = self._prepare_query_request(
            target=target,
            id=id,
            query_parameters=query_parameters,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = self.client.get(
                req.url, params=req.payload, **req.request_kwargs
            )

        with handle_response_error(response):
            return cast(
                "Resource[Any] | ListResponse[Resource[Any]] | Error | dict[str, Any]",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=req.expected_status_codes,
                    expected_types=req.expected_types,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                    scim_ctx=Context.RESOURCE_QUERY_RESPONSE,
                    target=req.target,
                ),
            )

    def search(
        self,
        search_request: SearchRequest[Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.SEARCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> Resource[Any] | ListResponse[Resource[Any]] | Error | dict[str, Any]:
        req = self._prepare_search_request(
            search_request=search_request,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = self.client.post(req.url, json=req.payload, **req.request_kwargs)

        with handle_response_error(response):
            return cast(
                "Resource[Any] | ListResponse[Resource[Any]] | Error | dict[str, Any]",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=req.expected_status_codes,
                    expected_types=req.expected_types,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                    scim_ctx=Context.RESOURCE_QUERY_RESPONSE,
                ),
            )

    def bulk(
        self,
        bulk_request: BulkRequest[Resource[Any]] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.BULK_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> BulkResponse[Resource[Any]] | Error | dict[str, Any]:
        req = self._prepare_bulk_request(
            bulk_request=bulk_request,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = self.client.post(req.url, json=req.payload, **req.request_kwargs)

        with handle_response_error(response):
            return cast(
                "BulkResponse[Resource[Any]] | Error | dict[str, Any]",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=req.expected_status_codes,
                    expected_types=req.expected_types,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                    scim_ctx=Context.BULK_RESPONSE,
                ),
            )

    def delete(
        self,
        resource: Resource[Any] | type[Resource[Any]] | None = None,
        id: str | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.DELETION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> Error | dict[str, Any] | None:
        req = self._prepare_delete_request(
            resource=resource,
            id=id,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error():
            response = self.client.delete(req.url, **req.request_kwargs)

        with handle_response_error(response):
            return cast(
                "Error | dict[str, Any] | None",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=expected_status_codes,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                ),
            )

    def replace(
        self,
        resource: AnyResource | dict[str, Any],
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.REPLACEMENT_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> AnyResource | Error | dict[str, Any]:
        req = self._prepare_replace_request(
            resource=resource,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = self.client.put(req.url, json=req.payload, **req.request_kwargs)

        with handle_response_error(response):
            return cast(
                "AnyResource | Error | dict[str, Any]",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=req.expected_status_codes,
                    expected_types=req.expected_types,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                    scim_ctx=Context.RESOURCE_REPLACEMENT_RESPONSE,
                ),
            )

    def modify(
        self,
        resource: ResourceT | type[ResourceT] | None = None,
        patch_op: PatchOp[ResourceT] | dict[str, Any] | None = None,
        id: str | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.PATCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any] | None:
        req = self._prepare_patch_request(
            resource=resource,
            patch_op=patch_op,
            id=id,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = self.client.patch(
                req.url, json=req.payload, **req.request_kwargs
            )

        with handle_response_error(response):
            return cast(
                "ResourceT | Error | dict[str, Any] | None",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=req.expected_status_codes,
                    expected_types=req.expected_types,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                    scim_ctx=Context.RESOURCE_PATCH_RESPONSE,
                ),
            )

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

    async def create(
        self,
        resource: AnyResource | dict[str, Any],
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.CREATION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> AnyResource | Error | dict[str, Any]:
        req = self._prepare_create_request(
            resource=resource,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = await self.client.post(
                req.url, json=req.payload, **req.request_kwargs
            )

        with handle_response_error(response):
            return cast(
                "AnyResource | Error | dict[str, Any]",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=req.expected_status_codes,
                    expected_types=req.expected_types,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                    scim_ctx=Context.RESOURCE_CREATION_RESPONSE,
                ),
            )

    async def query(
        self,
        target: type[Resource[Any]] | Resource[Any] | None = None,
        id: str | None = None,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.QUERY_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> Resource[Any] | ListResponse[Resource[Any]] | Error | dict[str, Any]:
        req = self._prepare_query_request(
            target=target,
            id=id,
            query_parameters=query_parameters,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = await self.client.get(
                req.url, params=req.payload, **req.request_kwargs
            )

        with handle_response_error(response):
            return cast(
                "Resource[Any] | ListResponse[Resource[Any]] | Error | dict[str, Any]",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=req.expected_status_codes,
                    expected_types=req.expected_types,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                    scim_ctx=Context.RESOURCE_QUERY_RESPONSE,
                    target=req.target,
                ),
            )

    async def search(
        self,
        search_request: SearchRequest[Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.SEARCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> Resource[Any] | ListResponse[Resource[Any]] | Error | dict[str, Any]:
        req = self._prepare_search_request(
            search_request=search_request,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = await self.client.post(
                req.url, json=req.payload, **req.request_kwargs
            )

        with handle_response_error(response):
            return cast(
                "Resource[Any] | ListResponse[Resource[Any]] | Error | dict[str, Any]",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=req.expected_status_codes,
                    expected_types=req.expected_types,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                    scim_ctx=Context.RESOURCE_QUERY_RESPONSE,
                ),
            )

    async def bulk(
        self,
        bulk_request: BulkRequest[Resource[Any]] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.BULK_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> BulkResponse[Resource[Any]] | Error | dict[str, Any]:
        req = self._prepare_bulk_request(
            bulk_request=bulk_request,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = await self.client.post(
                req.url, json=req.payload, **req.request_kwargs
            )

        with handle_response_error(response):
            return cast(
                "BulkResponse[Resource[Any]] | Error | dict[str, Any]",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=req.expected_status_codes,
                    expected_types=req.expected_types,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                    scim_ctx=Context.BULK_RESPONSE,
                ),
            )

    async def delete(
        self,
        resource: Resource[Any] | type[Resource[Any]] | None = None,
        id: str | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.DELETION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> Error | dict[str, Any] | None:
        req = self._prepare_delete_request(
            resource=resource,
            id=id,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error():
            response = await self.client.delete(req.url, **req.request_kwargs)

        with handle_response_error(response):
            return cast(
                "Error | dict[str, Any] | None",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=expected_status_codes,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                ),
            )

    async def replace(
        self,
        resource: AnyResource | dict[str, Any],
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.REPLACEMENT_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> AnyResource | Error | dict[str, Any]:
        req = self._prepare_replace_request(
            resource=resource,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = await self.client.put(
                req.url, json=req.payload, **req.request_kwargs
            )

        with handle_response_error(response):
            return cast(
                "AnyResource | Error | dict[str, Any]",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=req.expected_status_codes,
                    expected_types=req.expected_types,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                    scim_ctx=Context.RESOURCE_REPLACEMENT_RESPONSE,
                ),
            )

    async def modify(
        self,
        resource: ResourceT | type[ResourceT] | None = None,
        patch_op: PatchOp[ResourceT] | dict[str, Any] | None = None,
        id: str | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.PATCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any] | None:
        req = self._prepare_patch_request(
            resource=resource,
            patch_op=patch_op,
            id=id,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = await self.client.patch(
                req.url, json=req.payload, **req.request_kwargs
            )

        with handle_response_error(response):
            return cast(
                "ResourceT | Error | dict[str, Any] | None",
                self.check_response(
                    payload=decode_payload(response),
                    status_code=response.status_code,
                    headers=response.headers,
                    expected_status_codes=req.expected_status_codes,
                    expected_types=req.expected_types,
                    check_response_payload=check_response_payload,
                    raise_scim_errors=raise_scim_errors,
                    scim_ctx=Context.RESOURCE_PATCH_RESPONSE,
                ),
            )

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:
        with handle_request_error():
            return await self.client.request(method, url, **kwargs)
