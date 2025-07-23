import json
from contextlib import contextmanager
from typing import Optional
from typing import TypeVar
from typing import Union
from urllib.parse import urlencode

from scim2_models import AnyResource
from scim2_models import Context
from scim2_models import Error
from scim2_models import ListResponse
from scim2_models import PatchOp
from scim2_models import Resource
from scim2_models import SearchRequest
from werkzeug.test import Client

from scim2_client.client import BaseSyncSCIMClient
from scim2_client.errors import SCIMClientError
from scim2_client.errors import UnexpectedContentFormat

ResourceT = TypeVar("ResourceT", bound=Resource)


@contextmanager
def handle_response_error(response):
    try:
        yield

    except json.decoder.JSONDecodeError as exc:
        raise UnexpectedContentFormat(source=response) from exc

    except SCIMClientError as exc:
        exc.source = response
        raise exc


class TestSCIMClient(BaseSyncSCIMClient):
    """A client based on :class:`Werkzeug test Client <werkzeug.test.Client>` for application development purposes.

    This is helpful for developers of SCIM servers.
    This client avoids to perform real HTTP requests and directly execute the server code instead.
    This allows to dynamically catch the exceptions if something gets wrong.

    :param client: An optional custom :class:`Werkzeug test Client <werkzeug.test.Client>`.
        If :data:`None` a default client is initialized.
    :param scim_prefix: The scim root endpoint in the application.
    :param environ: Additional parameters that will be passed to every request.
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

    .. code-block:: python

        from scim2_client.engines.werkzeug import TestSCIMClient
        from scim2_models import User, Group
        from werkzeug.test import Client

        scim_provider = myapp.create_app()
        testclient = TestSCIMClient(
            app=Client(scim_provider),
            environ={"base_url": "/scim/v2"},
            resource_models=(User, Group),
        )

        request_user = User(user_name="foo", display_name="bar")
        response_user = scim_client.create(request_user)
        assert response_user.user_name == "foo"
    """

    # avoid making Pytest believe this is a test class
    __test__ = False

    def __init__(
        self,
        client: Client,
        environ: Optional[dict] = None,
        scim_prefix: str = "",
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.client = client
        self.scim_prefix = scim_prefix
        self.environ = environ or {}

    def _make_url(self, url: Optional[str]) -> str:
        url = url or ""
        prefix = (
            self.scim_prefix[:-1]
            if self.scim_prefix.endswith("/")
            else self.scim_prefix
        )
        return (
            url
            if url.startswith("http://") or url.startswith("https://")
            else f"{prefix}{url}"
        )

    def create(
        self,
        resource: Union[AnyResource, dict],
        check_request_payload: Optional[bool] = None,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = BaseSyncSCIMClient.CREATION_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Union[AnyResource, Error, dict]:
        req = self._prepare_create_request(
            resource=resource,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        environ = {**self.environ, **req.request_kwargs}
        response = self.client.post(
            self._make_url(req.url), json=req.payload, **environ
        )

        with handle_response_error(req.payload):
            return self.check_response(
                payload=response.json if response.text else None,
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
        resource_model: Optional[type[Resource]] = None,
        id: Optional[str] = None,
        search_request: Optional[Union[SearchRequest, dict]] = None,
        check_request_payload: Optional[bool] = None,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = BaseSyncSCIMClient.QUERY_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ):
        req = self._prepare_query_request(
            resource_model=resource_model,
            id=id,
            search_request=search_request,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        query_string = urlencode(req.payload, doseq=False) if req.payload else None
        environ = {**self.environ, **req.request_kwargs}
        response = self.client.get(
            self._make_url(req.url), query_string=query_string, **environ
        )

        with handle_response_error(req.payload):
            return self.check_response(
                payload=response.json if response.text else None,
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
        search_request: Optional[SearchRequest] = None,
        check_request_payload: Optional[bool] = None,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = BaseSyncSCIMClient.SEARCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Union[AnyResource, ListResponse[AnyResource], Error, dict]:
        req = self._prepare_search_request(
            search_request=search_request,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        environ = {**self.environ, **req.request_kwargs}
        response = self.client.post(
            self._make_url(req.url), json=req.payload, **environ
        )

        with handle_response_error(response):
            return self.check_response(
                payload=response.json if response.text else None,
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
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = BaseSyncSCIMClient.DELETION_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Optional[Union[Error, dict]]:
        req = self._prepare_delete_request(
            resource_model=resource_model,
            id=id,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        environ = {**self.environ, **req.request_kwargs}
        response = self.client.delete(self._make_url(req.url), **environ)

        with handle_response_error(response):
            return self.check_response(
                payload=response.json if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=req.expected_status_codes,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
            )

    def replace(
        self,
        resource: Union[AnyResource, dict],
        check_request_payload: Optional[bool] = None,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = BaseSyncSCIMClient.REPLACEMENT_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Union[AnyResource, Error, dict]:
        req = self._prepare_replace_request(
            resource=resource,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        environ = {**self.environ, **req.request_kwargs}
        response = self.client.put(self._make_url(req.url), json=req.payload, **environ)

        with handle_response_error(response):
            return self.check_response(
                payload=response.json if response.text else None,
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
        patch_op: Union[PatchOp[ResourceT], dict],
        check_request_payload: Optional[bool] = None,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = BaseSyncSCIMClient.PATCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Optional[Union[ResourceT, Error, dict]]:
        req = self._prepare_patch_request(
            resource_model=resource_model,
            id=id,
            patch_op=patch_op,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )

        environ = {**self.environ, **req.request_kwargs}
        response = self.client.patch(
            self._make_url(req.url), json=req.payload, **environ
        )

        with handle_response_error(response):
            return self.check_response(
                payload=response.json if response.text else None,
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=req.expected_status_codes,
                expected_types=req.expected_types,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
                scim_ctx=Context.RESOURCE_PATCH_RESPONSE,
            )
