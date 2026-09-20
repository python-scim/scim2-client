import json
import sys
import warnings
from contextlib import contextmanager
from typing import Any
from typing import TypeVar

try:
    from httpx2 import AsyncClient
    from httpx2 import Client
    from httpx2 import Response
except ImportError:
    warnings.warn(
        "httpx2 is not installed, falling back on httpx. "
        "The httpx support is deprecated, install 'scim2-client[httpx2]' instead. "
        "Will be removed in 0.9.",
        DeprecationWarning,
        stacklevel=2,
    )
    from httpx import AsyncClient  # type: ignore[assignment]
    from httpx import Client  # type: ignore[assignment]
    from httpx import Response  # type: ignore[assignment]

from scim2_models import AnyResource
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

ResourceT = TypeVar("ResourceT", bound=Resource)


def _request_error_classes() -> tuple[type[BaseException], ...]:
    """Return the ``RequestError`` classes of the httpx flavors that are in use."""
    modules: tuple[Any, ...] = (sys.modules.get("httpx2"), sys.modules.get("httpx"))
    return tuple(module.RequestError for module in modules if module is not None)


def _warn_legacy_client(client: Any) -> None:
    """Warn when a httpx client is used while httpx2 is the flavor in use."""
    httpx: Any = sys.modules.get("httpx")
    if httpx is None or Client is httpx.Client:
        return

    if not isinstance(client, (httpx.Client, httpx.AsyncClient)):
        return

    warnings.warn(
        "Passing a httpx client is deprecated, pass a httpx2 client instead. "
        "Will be removed in 0.9.",
        DeprecationWarning,
        stacklevel=3,
    )


@contextmanager
def handle_request_error(payload=None):
    try:
        yield

    except _request_error_classes() as exc:
        scim_network_exc = RequestNetworkException(source=payload)
        if sys.version_info >= (3, 11):  # pragma: no cover
            scim_network_exc.add_note(str(exc))
        raise scim_network_exc from exc


@contextmanager
def handle_response_error(response: Response):
    try:
        yield

    except json.decoder.JSONDecodeError as exc:
        raise UnexpectedContentFormatException(source=response) from exc

    except (SCIMClientException, SCIMException) as exc:
        exc.source = response
        raise exc


class SyncSCIMClient(BaseSyncSCIMClient):
    """Perform SCIM requests over the network and validate responses.

    :param client: A :class:`httpx2.Client` instance that will be used to send requests.
    :param resource_models: A tuple of :class:`~scim2_models.Resource` types expected to be handled by the SCIM client.
        If a request payload describe a resource that is not in this list, an exception will be raised.
    :param check_request_payload: If :data:`False`,
        :code:`resource` is expected to be a dict that will be passed as-is in the request.
        This value can be overwritten in methods.
    :param check_response_payload: Whether to validate that the response payloads are valid.
        If set, the raw payload will be returned. This value can be overwritten in methods.
    :param raise_scim_errors: If :data:`True` and the server returned an
        :class:`~scim2_models.Error` object during a request, a :class:`~scim2_models.SCIMException`
        exception will be raised. If :data:`False` the error object is returned. This value can be overwritten in methods.
    """

    def __init__(self, client: Client, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _warn_legacy_client(client)
        self.client = client

    def create(
        self,
        resource: AnyResource | dict,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.CREATION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> AnyResource | Error | dict:
        req = self._prepare_create_request(
            resource=resource,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = self.client.post(req.url, json=req.payload, **req.request_kwargs)

        with handle_response_error(response):
            return self.check_response(
                payload=response.json() if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=req.expected_status_codes,
                expected_types=req.expected_types,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
                scim_ctx=Context.RESOURCE_CREATION_RESPONSE,
            )

    def query(
        self,
        target: type[Resource] | Resource | None = None,
        id: str | None = None,
        query_parameters: ResponseParameters | dict | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.QUERY_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        search_request: ResponseParameters | dict | None = None,
        **kwargs,
    ) -> Resource | ListResponse[Resource] | Error | dict:
        query_parameters = self._resolve_query_parameters(
            query_parameters, search_request
        )
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
            return self.check_response(
                payload=response.json() if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=req.expected_status_codes,
                expected_types=req.expected_types,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
                scim_ctx=Context.RESOURCE_QUERY_RESPONSE,
                target=req.target,
            )

    def search(
        self,
        search_request: SearchRequest | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.SEARCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> Resource | ListResponse[Resource] | Error | dict:
        req = self._prepare_search_request(
            search_request=search_request,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = self.client.post(req.url, json=req.payload, **req.request_kwargs)

        with handle_response_error(response):
            return self.check_response(
                payload=response.json() if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=req.expected_status_codes,
                expected_types=req.expected_types,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
                scim_ctx=Context.RESOURCE_QUERY_RESPONSE,
            )

    def delete(
        self,
        resource: Resource | type[Resource] | None = None,
        id: str | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.DELETION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> Error | dict | None:
        req = self._prepare_delete_request(
            resource=resource,
            id=id,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error():
            response = self.client.delete(req.url, **req.request_kwargs)

        with handle_response_error(response):
            return self.check_response(
                payload=response.json() if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=expected_status_codes,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
            )

    def replace(
        self,
        resource: AnyResource | dict,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.REPLACEMENT_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> AnyResource | Error | dict:
        req = self._prepare_replace_request(
            resource=resource,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = self.client.put(req.url, json=req.payload, **req.request_kwargs)

        with handle_response_error(response):
            return self.check_response(
                payload=response.json() if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=req.expected_status_codes,
                expected_types=req.expected_types,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
                scim_ctx=Context.RESOURCE_REPLACEMENT_RESPONSE,
            )

    def modify(
        self,
        resource: ResourceT | type[ResourceT] | None = None,
        patch_op: PatchOp[ResourceT] | dict | None = None,
        id: str | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.PATCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> ResourceT | Error | dict | None:
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
            return self.check_response(
                payload=response.json() if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=req.expected_status_codes,
                expected_types=req.expected_types,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
                scim_ctx=Context.RESOURCE_PATCH_RESPONSE,
            )


class AsyncSCIMClient(BaseAsyncSCIMClient):
    """Perform SCIM requests over the network and validate responses.

    :param client: A :class:`httpx2.AsyncClient` instance that will be used to send requests.
    :param resource_models: A tuple of :class:`~scim2_models.Resource` types expected to be handled by the SCIM client.
        If a request payload describe a resource that is not in this list, an exception will be raised.
    :param check_request_payload: If :data:`False`,
        :code:`resource` is expected to be a dict that will be passed as-is in the request.
        This value can be overwritten in methods.
    :param check_response_payload: Whether to validate that the response payloads are valid.
        If set, the raw payload will be returned. This value can be overwritten in methods.
    :param raise_scim_errors: If :data:`True` and the server returned an
        :class:`~scim2_models.Error` object during a request, a :class:`~scim2_models.SCIMException`
        exception will be raised. If :data:`False` the error object is returned. This value can be overwritten in methods.

    """

    def __init__(self, client: AsyncClient, *args, **kwargs):
        super().__init__(*args, **kwargs)
        _warn_legacy_client(client)
        self.client = client

    async def create(
        self,
        resource: AnyResource | dict,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.CREATION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> AnyResource | Error | dict:
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
            return self.check_response(
                payload=response.json() if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=req.expected_status_codes,
                expected_types=req.expected_types,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
                scim_ctx=Context.RESOURCE_CREATION_RESPONSE,
            )

    async def query(
        self,
        target: type[Resource] | Resource | None = None,
        id: str | None = None,
        query_parameters: ResponseParameters | dict | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.QUERY_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        search_request: ResponseParameters | dict | None = None,
        **kwargs,
    ) -> Resource | ListResponse[Resource] | Error | dict:
        query_parameters = self._resolve_query_parameters(
            query_parameters, search_request
        )
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
            return self.check_response(
                payload=response.json() if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=req.expected_status_codes,
                expected_types=req.expected_types,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
                scim_ctx=Context.RESOURCE_QUERY_RESPONSE,
                target=req.target,
            )

    async def search(
        self,
        search_request: SearchRequest | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.SEARCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> Resource | ListResponse[Resource] | Error | dict:
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
            return self.check_response(
                payload=response.json() if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=req.expected_status_codes,
                expected_types=req.expected_types,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
                scim_ctx=Context.RESOURCE_QUERY_RESPONSE,
            )

    async def delete(
        self,
        resource: Resource | type[Resource] | None = None,
        id: str | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.DELETION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> Error | dict | None:
        req = self._prepare_delete_request(
            resource=resource,
            id=id,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error():
            response = await self.client.delete(req.url, **req.request_kwargs)

        with handle_response_error(response):
            return self.check_response(
                payload=response.json() if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=expected_status_codes,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
            )

    async def replace(
        self,
        resource: AnyResource | dict,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.REPLACEMENT_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> AnyResource | Error | dict:
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
            return self.check_response(
                payload=response.json() if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=req.expected_status_codes,
                expected_types=req.expected_types,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
                scim_ctx=Context.RESOURCE_REPLACEMENT_RESPONSE,
            )

    async def modify(
        self,
        resource: ResourceT | type[ResourceT] | None = None,
        patch_op: PatchOp[ResourceT] | dict | None = None,
        id: str | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.PATCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> ResourceT | Error | dict | None:
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
            return self.check_response(
                payload=response.json() if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=req.expected_status_codes,
                expected_types=req.expected_types,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
                scim_ctx=Context.RESOURCE_PATCH_RESPONSE,
            )
