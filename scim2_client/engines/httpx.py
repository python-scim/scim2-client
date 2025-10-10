import json
import sys
from contextlib import contextmanager
from typing import TypeVar

from httpx import Client
from httpx import RequestError
from httpx import Response
from scim2_models import AnyResource
from scim2_models import Context
from scim2_models import Error
from scim2_models import ListResponse
from scim2_models import PatchOp
from scim2_models import Resource
from scim2_models import SearchRequest

from scim2_client.client import BaseAsyncSCIMClient
from scim2_client.client import BaseSyncSCIMClient
from scim2_client.errors import RequestNetworkError
from scim2_client.errors import SCIMClientError
from scim2_client.errors import UnexpectedContentFormat

ResourceT = TypeVar("ResourceT", bound=Resource)


@contextmanager
def handle_request_error(payload=None):
    try:
        yield

    except RequestError as exc:
        scim_network_exc = RequestNetworkError(source=payload)
        if sys.version_info >= (3, 11):  # pragma: no cover
            scim_network_exc.add_note(str(exc))
        raise scim_network_exc from exc


@contextmanager
def handle_response_error(response: Response):
    try:
        yield

    except json.decoder.JSONDecodeError as exc:
        raise UnexpectedContentFormat(source=response) from exc

    except SCIMClientError as exc:
        exc.source = response
        raise exc


class SyncSCIMClient(BaseSyncSCIMClient):
    """Perform SCIM requests over the network and validate responses.

    :param client: A :class:`httpx.Client` instance that will be used to send requests.
    :param resource_models: A tuple of :class:`~scim2_models.Resource` types expected to be handled by the SCIM client.
        If a request payload describe a resource that is not in this list, an exception will be raised.
    :param check_request_payload: If :data:`False`,
        :code:`resource` is expected to be a dict that will be passed as-is in the request.
        This value can be overwritten in methods.
    :param check_response_payload: Whether to validate that the response payloads are valid.
        If set, the raw payload will be returned. This value can be overwritten in methods.
    :param raise_scim_errors: If :data:`True` and the server returned an
        :class:`~scim2_models.Error` object during a request, a :class:`~scim2_client.SCIMResponseErrorObject`
        exception will be raised. If :data:`False` the error object is returned. This value can be overwritten in methods.
    """

    def __init__(self, client: Client, *args, **kwargs):
        super().__init__(*args, **kwargs)
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

        with handle_response_error(req.payload):
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
        resource_model: type[AnyResource] | None = None,
        id: str | None = None,
        search_request: SearchRequest | dict | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.QUERY_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> AnyResource | ListResponse[AnyResource] | Error | dict:
        req = self._prepare_query_request(
            resource_model=resource_model,
            id=id,
            search_request=search_request,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = self.client.get(
                req.url, params=req.payload, **req.request_kwargs
            )

        with handle_response_error(req.payload):
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

    def search(
        self,
        search_request: SearchRequest | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.SEARCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> AnyResource | ListResponse[AnyResource] | Error | dict:
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
        resource_model: type,
        id: str,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.DELETION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> Error | dict | None:
        req = self._prepare_delete_request(
            resource_model=resource_model,
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
        resource_model: type[ResourceT],
        id: str,
        patch_op: PatchOp[ResourceT] | dict,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseSyncSCIMClient.PATCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> ResourceT | Error | dict | None:
        req = self._prepare_patch_request(
            resource_model=resource_model,
            id=id,
            patch_op=patch_op,
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

    :param client: A :class:`httpx.AsyncClient` instance that will be used to send requests.
    :param resource_models: A tuple of :class:`~scim2_models.Resource` types expected to be handled by the SCIM client.
        If a request payload describe a resource that is not in this list, an exception will be raised.
    :param check_request_payload: If :data:`False`,
        :code:`resource` is expected to be a dict that will be passed as-is in the request.
        This value can be overwritten in methods.
    :param check_response_payload: Whether to validate that the response payloads are valid.
        If set, the raw payload will be returned. This value can be overwritten in methods.
    :param raise_scim_errors: If :data:`True` and the server returned an
        :class:`~scim2_models.Error` object during a request, a :class:`~scim2_client.SCIMResponseErrorObject`
        exception will be raised. If :data:`False` the error object is returned. This value can be overwritten in methods.

    """

    def __init__(self, client: Client, *args, **kwargs):
        super().__init__(*args, **kwargs)
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

        with handle_response_error(req.payload):
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
        resource_model: type[Resource] | None = None,
        id: str | None = None,
        search_request: SearchRequest | dict | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.QUERY_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> AnyResource | ListResponse[AnyResource] | Error | dict:
        req = self._prepare_query_request(
            resource_model=resource_model,
            id=id,
            search_request=search_request,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        with handle_request_error(req.payload):
            response = await self.client.get(
                req.url, params=req.payload, **req.request_kwargs
            )

        with handle_response_error(req.payload):
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

    async def search(
        self,
        search_request: SearchRequest | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.SEARCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> AnyResource | ListResponse[AnyResource] | Error | dict:
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
        resource_model: type,
        id: str,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.DELETION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> Error | dict | None:
        req = self._prepare_delete_request(
            resource_model=resource_model,
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
        resource_model: type[ResourceT],
        id: str,
        patch_op: PatchOp[ResourceT] | dict,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = BaseAsyncSCIMClient.PATCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> ResourceT | Error | dict | None:
        req = self._prepare_patch_request(
            resource_model=resource_model,
            id=id,
            patch_op=patch_op,
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
