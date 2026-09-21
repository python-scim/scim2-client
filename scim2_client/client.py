import asyncio
import json
import sys
import warnings
from collections.abc import Collection
from dataclasses import dataclass
from typing import TypeVar
from typing import Union
from typing import cast

from pydantic import ValidationError
from scim2_models import AnyResource
from scim2_models import Bulk
from scim2_models import BulkRequest
from scim2_models import BulkResponse
from scim2_models import Context
from scim2_models import Error
from scim2_models import Extension
from scim2_models import InvalidValueException
from scim2_models import ListResponse
from scim2_models import Meta
from scim2_models import PatchOp
from scim2_models import Resource
from scim2_models import ResourceType
from scim2_models import ResponseParameters
from scim2_models import Schema
from scim2_models import SearchRequest
from scim2_models import ServiceProviderConfig
from scim2_models import get_model_by_payload

from scim2_client.errors import ResponsePayloadValidationException
from scim2_client.errors import SCIMResponseException
from scim2_client.errors import UnexpectedContentTypeException
from scim2_client.errors import UnexpectedStatusCodeException
from scim2_client.errors import request_validation_exception
from scim2_client.errors import server_error_exception

ResourceT = TypeVar("ResourceT", bound=Resource)

NOT_MODIFIED = 304

BASE_HEADERS = {
    "Accept": "application/scim+json",
    "Content-Type": "application/scim+json",
}
CONFIG_RESOURCES = (ResourceType, Schema, ServiceProviderConfig)


@dataclass
class RequestPayload:
    request_kwargs: dict
    url: str | None = None
    payload: dict | None = None
    expected_types: list[type[Resource]] | None = None
    expected_status_codes: list[int] | None = None
    target: Resource | None = None


class SCIMClient:
    """The base model for request clients.

    It goal is to parse the requests and responses and check if they comply with the SCIM specifications.

    This class can be inherited and used as a basis for request engine integration.

    :param resource_models: A collection of :class:`~scim2_models.Resource` models expected to be handled by the SCIM client.
        If a request payload describe a resource that is not in this list, an exception will be raised.
    :param resource_types: A collection of :class:`~scim2_models.ResourceType` that will be used to guess the
        server endpoints associated with the resources.
    :param service_provider_config: An instance of :class:`~scim2_models.ServiceProviderConfig`.
    :param check_request_payload: If :data:`False`,
        :code:`resource` is expected to be a dict that will be passed as-is in the request.
        This value can be overwritten in methods.
    :param check_response_payload: Whether to validate that the response payloads are valid.
        If set, the raw payload will be returned. This value can be overwritten in methods.
    :param check_response_content_type: Whether to validate that the response content types are valid.
    :param check_response_status_codes: Whether to validate that the response status codes are valid.
    :param raise_scim_errors: If :data:`True` and the server returned an
        :class:`~scim2_models.Error` object during a request, a :class:`~scim2_models.SCIMException`
        exception will be raised. If :data:`False` the error object is returned. This value can be overwritten in methods.

    .. note::

        :class:`~scim2_models.ResourceType`, :class:`~scim2_models.Schema` and :class:`scim2_models.ServiceProviderConfig` are pre-loaded by default.
    """

    CREATION_RESPONSE_STATUS_CODES: list[int] = [
        201,
        409,
        307,
        308,
        400,
        401,
        403,
        404,
        500,
    ]
    """Resource creation HTTP codes.

    As defined at :rfc:`RFC7644 §3.3 <7644#section-3.3>` and
    :rfc:`RFC7644 §3.12 <7644#section-3.12>`.
    """

    QUERY_RESPONSE_STATUS_CODES: list[int] = [
        200,
        304,
        307,
        308,
        400,
        401,
        403,
        404,
        500,
    ]
    """Resource querying HTTP codes.

    As defined at :rfc:`RFC7644 §3.4.2 <7644#section-3.4.2>`,
    :rfc:`RFC7644 §3.12 <7644#section-3.12>` and
    :rfc:`RFC7644 §3.14 <7644#section-3.14>`.
    """

    SEARCH_RESPONSE_STATUS_CODES: list[int] = [
        200,
        307,
        308,
        400,
        401,
        403,
        404,
        409,
        413,
        500,
        501,
    ]
    """Resource querying HTTP codes.

    As defined at :rfc:`RFC7644 §3.4.3 <7644#section-3.4.3>` and
    :rfc:`RFC7644 §3.12 <7644#section-3.12>`.
    """

    BULK_RESPONSE_STATUS_CODES: list[int] = [
        200,
        307,
        308,
        400,
        401,
        403,
        404,
        409,
        413,
        500,
        501,
    ]
    """Bulk request HTTP codes.

    As defined at :rfc:`RFC7644 §3.7 <7644#section-3.7>` and
    :rfc:`RFC7644 §3.12 <7644#section-3.12>`.
    """

    DELETION_RESPONSE_STATUS_CODES: list[int] = [
        204,
        307,
        308,
        400,
        401,
        403,
        404,
        409,
        412,
        500,
        501,
    ]
    """Resource deletion HTTP codes.

    As defined at :rfc:`RFC7644 §3.6 <7644#section-3.6>` and
    :rfc:`RFC7644 §3.12 <7644#section-3.12>`.
    """

    REPLACEMENT_RESPONSE_STATUS_CODES: list[int] = [
        200,
        307,
        308,
        400,
        401,
        403,
        404,
        409,
        412,
        500,
        501,
    ]
    """Resource querying HTTP codes.

    As defined at :rfc:`RFC7644 §3.4.2 <7644#section-3.4.2>` and
    :rfc:`RFC7644 §3.12 <7644#section-3.12>`.
    """

    PATCH_RESPONSE_STATUS_CODES: list[int] = [
        200,
        204,
        307,
        308,
        400,
        401,
        403,
        404,
        409,
        412,
        500,
        501,
    ]
    """Resource patching HTTP codes.

    As defined at :rfc:`RFC7644 §3.5.2 <7644#section-3.5.2>` and
    :rfc:`RFC7644 §3.12 <7644#section-3.12>`.
    """

    def __init__(
        self,
        resource_models: Collection[type[Resource]] | None = None,
        resource_types: Collection[ResourceType] | None = None,
        service_provider_config: ServiceProviderConfig | None = None,
        check_request_payload: bool = True,
        check_response_payload: bool = True,
        check_response_content_type: bool = True,
        check_response_status_codes: bool = True,
        raise_scim_errors: bool = True,
    ):
        self.resource_models = tuple(resource_models or [])
        self.resource_types = resource_types
        self.service_provider_config = service_provider_config
        self.check_request_payload = check_request_payload
        self.check_response_payload = check_response_payload
        self.check_response_content_type = check_response_content_type
        self.check_response_status_codes = check_response_status_codes
        self.raise_scim_errors = raise_scim_errors

    def get_resource_model(self, name: str) -> type[Resource] | None:
        """Get a registered model by its name or its schema."""
        for resource_model in self.resource_models:
            schema = resource_model.__schema__
            if schema == name or schema.split(":")[-1] == name:
                return resource_model
        return None

    def _check_resource_model(self, resource_model: type[Resource]) -> None:
        schema_to_check = resource_model.__schema__
        for element in self.resource_models:
            schema = element.__schema__
            if schema_to_check == schema:
                return

        if resource_model not in CONFIG_RESOURCES:
            raise InvalidValueException(
                detail=f"Unknown resource type: '{resource_model}'"
            )

    @staticmethod
    def _resolve_deprecated_resource_model(
        target: type[Resource] | Resource | None, kwargs: dict
    ) -> type[Resource] | Resource | None:
        """Read the target from the deprecated ``resource_model`` parameter."""
        resource_model = kwargs.pop("resource_model", None)
        if resource_model is None:
            return target

        if target is not None:
            raise TypeError(
                "Cannot pass both a resource and the deprecated 'resource_model'"
            )

        warnings.warn(
            "The 'resource_model' parameter is deprecated, pass the resource type "
            "or a resource object as the first parameter instead. "
            "Will be removed in 0.9.",
            DeprecationWarning,
            stacklevel=4,
        )
        return resource_model

    @property
    def _etag_supported(self) -> bool:
        spc = self.service_provider_config
        return bool(spc and spc.etag and spc.etag.supported)

    @staticmethod
    def _resource_version(resource: Resource | dict | None) -> str | None:
        """Read the ETag a resource was read with."""
        if isinstance(resource, Resource):
            return resource.meta.version if resource.meta else None

        if isinstance(resource, dict):
            return (resource.get("meta") or {}).get("version")

        return None

    def _set_if_match(self, req: RequestPayload, resource: Resource | dict | None):
        """Make a write request conditional on the resource not having changed."""
        version = self._resource_version(resource)
        if not version or not self._etag_supported:
            return

        headers = req.request_kwargs.setdefault("headers", {})
        headers.setdefault("If-Match", version)

    def _set_if_none_match(self, req: RequestPayload, resource: Resource):
        """Make a read request conditional on the resource having changed."""
        version = self._resource_version(resource)
        if not version or not self._etag_supported:
            return

        req.target = resource
        headers = req.request_kwargs.setdefault("headers", {})
        headers.setdefault("If-None-Match", version)

    @staticmethod
    def _set_version_from_etag(result, headers: dict):
        """Fill an empty resource version with the ETag header of the response.

        RFC7644 3.14 makes the ETag header mandatory when versioning is
        supported, but only recommends filling the meta.version attribute.
        """
        etag = headers.get("etag")
        if not etag or not isinstance(result, Resource):
            return

        if result.meta is None:
            result.meta = Meta()

        if not result.meta.version:
            result.meta.version = etag

    @staticmethod
    def _resolve_patch_arguments(
        patch_op: PatchOp | dict | str | None, id: str | None
    ) -> tuple[PatchOp | dict | None, str | None]:
        """Tell ``modify(resource_model, id, patch_op)`` apart from ``modify(resource, patch_op)``.

        An id is never a valid patch operation, so the second parameter is
        enough to know which call style is used.
        """
        if not isinstance(patch_op, str):
            return patch_op, id

        # The id landed in 'patch_op' and the patch operation in 'id'.
        return cast("PatchOp | dict | None", id), patch_op

    @staticmethod
    def _resolve_target(
        target: type[Resource] | Resource | None, id: str | None
    ) -> tuple[type[Resource] | None, str | None, Resource | None]:
        """Read a resource type and an id, from either a resource object or a resource type and an id."""
        if not isinstance(target, Resource):
            return target, id, None

        if id is not None:
            raise InvalidValueException(
                detail="Cannot pass both a resource object and an id"
            )

        if not target.id:
            raise InvalidValueException(detail="Resource must have an id")

        return type(target), target.id, target

    def resource_endpoint(self, resource_model: type[Resource] | None) -> str:
        """Find the :attr:`~scim2_models.ResourceType.endpoint` associated with a given :class:`~scim2_models.Resource`.

        Internally, it looks if any :paramref:`resource_type <scim2_client.SCIMClient.resource_models>`
        of the client matches the resource_model by comparing schemas.
        """
        if resource_model is None:
            return "/"

        if resource_model in (ResourceType, Schema):
            return f"/{resource_model.__name__}s"

        # This one takes no final 's'
        if resource_model is ServiceProviderConfig:
            return "/ServiceProviderConfig"

        schema = resource_model.__schema__
        for resource_type in self.resource_types or []:
            if schema == resource_type.schema_:
                return resource_type.endpoint

        raise InvalidValueException(
            detail=f"No ResourceType is matching the schema: {schema}"
        )

    def register_naive_resource_types(self):
        """Register a *naive* :class:`~scim2_models.ResourceType` for each :paramref:`resource_model <scim2_client.SCIMClient.resource_models>`.

        This fills the :class:`~scim2_models.ResourceType` with generic values.
        The endpoint is the resource name with a *s* suffix.
        For instance, the :class:`~scim2_models.User` will have a `/Users` endpoint.
        """
        self.resource_types = [
            ResourceType.from_resource(model)
            for model in self.resource_models
            if model not in CONFIG_RESOURCES
        ]

    def _check_status_codes(
        self, status_code: int, expected_status_codes: list[int] | None
    ):
        if (
            self.check_response_status_codes
            and expected_status_codes
            and status_code not in expected_status_codes
        ):
            raise UnexpectedStatusCodeException(status_code)

    def _check_content_types(self, headers: dict):
        # Interoperability considerations:  The "application/scim+json" media
        # type is intended to identify JSON structure data that conforms to
        # the SCIM protocol and schema specifications.  Older versions of
        # SCIM are known to informally use "application/json".
        # https://datatracker.ietf.org/doc/html/rfc7644.html#section-8.1

        actual_content_type = headers.get("content-type", "").split(";").pop(0)
        expected_response_content_types = ("application/scim+json", "application/json")
        if (
            self.check_response_content_type
            and actual_content_type not in expected_response_content_types
        ):
            raise UnexpectedContentTypeException(content_type=actual_content_type)

    def check_response(
        self,
        payload: dict | None,
        status_code: int,
        headers: dict,
        expected_status_codes: list[int] | None = None,
        expected_types: list[type[Resource]] | None = None,
        check_response_payload: bool | None = None,
        raise_scim_errors: bool | None = None,
        scim_ctx: Context | None = None,
        target: Resource | None = None,
    ) -> Error | None | dict | type[Resource]:
        if raise_scim_errors is None:
            raise_scim_errors = self.raise_scim_errors

        # In addition to returning an HTTP response code, implementers MUST return
        # the errors in the body of the response in a JSON format
        # https://datatracker.ietf.org/doc/html/rfc7644.html#section-3.12

        no_content_status_codes = [204, 205, 304]
        if status_code in no_content_status_codes:
            response_payload = None

        else:
            self._check_content_types(headers)
            response_payload = payload

        if check_response_payload is None:
            check_response_payload = self.check_response_payload

        if not check_response_payload:
            self._check_status_codes(status_code, expected_status_codes)
            return response_payload

        if response_payload and response_payload.get("schemas") == [Error.__schema__]:
            error = Error.model_validate(response_payload)
            if raise_scim_errors:
                raise server_error_exception(error, scim_ctx=scim_ctx)
            return error

        self._check_status_codes(status_code, expected_status_codes)

        # The server states the resource did not change, so the object the
        # request was made conditional upon is still up to date.
        if status_code == NOT_MODIFIED and target is not None:
            return target

        if not expected_types:
            return response_payload

        # For no-content responses, return None directly
        if response_payload is None:
            return None

        actual_type = get_model_by_payload(
            expected_types, response_payload, with_extensions=False
        )

        if not actual_type:
            expected = ", ".join([type_.__name__ for type_ in expected_types])
            try:
                schema = ", ".join(response_payload["schemas"])
                message = f"Expected type {expected} but got unknown resource with schemas: {schema}"
            except KeyError:
                message = (
                    f"Expected type {expected} but got undefined object with no schema"
                )

            raise SCIMResponseException(message)

        try:
            result = actual_type.model_validate(response_payload, scim_ctx=scim_ctx)
        except ValidationError as exc:
            scim_exc = ResponsePayloadValidationException()
            if sys.version_info >= (3, 11):  # pragma: no cover
                scim_exc.add_note(str(exc))
            raise scim_exc from exc

        self._set_version_from_etag(result, headers)
        return result

    def _prepare_create_request(
        self,
        resource: Resource | dict,
        check_request_payload: bool | None = None,
        expected_status_codes: list[int] | None = None,
        **kwargs,
    ) -> RequestPayload:
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )
        if check_request_payload is None:
            check_request_payload = self.check_request_payload

        if not check_request_payload:
            req.payload = resource
            req.url = req.request_kwargs.pop("url", None)

        else:
            if isinstance(resource, Resource):
                resource_model = resource.__class__

            else:
                resource_model = get_model_by_payload(self.resource_models, resource)
                if not resource_model:
                    raise InvalidValueException(
                        detail="Cannot guess resource type from the payload"
                    )

                try:
                    resource = resource_model.model_validate(resource)
                except ValidationError as exc:
                    raise request_validation_exception(
                        exc, Context.RESOURCE_CREATION_REQUEST
                    ) from exc

            self._check_resource_model(resource_model)
            req.expected_types = [resource.__class__]
            req.url = req.request_kwargs.pop(
                "url", self.resource_endpoint(resource_model)
            )
            req.payload = resource.model_dump(
                scim_ctx=Context.RESOURCE_CREATION_REQUEST
            )

        return req

    @staticmethod
    def _resolve_query_parameters(
        query_parameters: ResponseParameters | dict | None,
        search_request: ResponseParameters | dict | None,
    ) -> ResponseParameters | dict | None:
        if search_request is not None:
            if query_parameters is not None:
                raise TypeError(
                    "Cannot pass both 'query_parameters' and "
                    "deprecated 'search_request'"
                )
            warnings.warn(
                "The 'search_request' parameter of 'query' is deprecated, "
                "use 'query_parameters' instead. "
                "Will be removed in 0.9.",
                DeprecationWarning,
                stacklevel=3,
            )
            return search_request
        return query_parameters

    def _prepare_query_request(
        self,
        target: type[Resource] | Resource | None = None,
        id: str | None = None,
        query_parameters: ResponseParameters | dict | None = None,
        check_request_payload: bool | None = None,
        expected_status_codes: list[int] | None = None,
        **kwargs,
    ) -> RequestPayload:
        target = self._resolve_deprecated_resource_model(target, kwargs)
        resource_model, id, resource = self._resolve_target(target, id)
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )

        if check_request_payload is None:
            check_request_payload = self.check_request_payload

        if resource_model and check_request_payload:
            self._check_resource_model(resource_model)

        payload: ResponseParameters | None
        if not check_request_payload:
            payload = query_parameters

        elif isinstance(query_parameters, SearchRequest):
            payload = query_parameters.model_dump(
                exclude_unset=True,
                exclude={"schemas"},
                scim_ctx=Context.RESOURCE_QUERY_REQUEST,
            )

        elif isinstance(query_parameters, ResponseParameters):
            payload = query_parameters.model_dump(
                exclude_unset=True,
                by_alias=True,
            )

        else:
            payload = None

        req.payload = payload
        req.url = req.request_kwargs.pop("url", self.resource_endpoint(resource_model))

        if resource_model is None:
            req.expected_types = [
                *self.resource_models,
                ListResponse[Union[self.resource_models]],  # noqa: UP007
            ]

        elif resource_model == ServiceProviderConfig:
            req.expected_types = [resource_model]
            if id:
                raise InvalidValueException(
                    detail="ServiceProviderConfig cannot have an id"
                )

        elif id:
            req.expected_types = [resource_model]
            req.url = f"{req.url}/{id}"
            # A 304 answer has no payload, so the object can only be returned
            # back when it is the whole resource that was asked for.
            if resource is not None and not payload:
                self._set_if_none_match(req, resource)

        else:
            req.expected_types = [ListResponse[resource_model]]

        return req

    def _prepare_search_request(
        self,
        search_request: SearchRequest | None = None,
        check_request_payload: bool | None = None,
        expected_status_codes: list[int] | None = None,
        **kwargs,
    ) -> RequestPayload:
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )

        if check_request_payload is None:
            check_request_payload = self.check_request_payload

        if not check_request_payload:
            req.payload = search_request

        else:
            req.payload = (
                search_request.model_dump(
                    exclude_unset=True, scim_ctx=Context.RESOURCE_QUERY_RESPONSE
                )
                if search_request
                else None
            )

        req.url = req.request_kwargs.pop("url", "/.search")
        req.expected_types = [ListResponse[Union[self.resource_models]]]  # noqa: UP007
        return req

    @property
    def _bulk_config(self) -> Bulk | None:
        """Read the bulk capabilities the server advertises, if they are known."""
        spc = self.service_provider_config
        return spc.bulk if spc else None

    def _check_bulk_support(self) -> None:
        """Refuse a bulk request the server advertised it does not serve."""
        bulk = self._bulk_config
        if bulk and bulk.supported is False:
            raise InvalidValueException(
                detail="The server does not support bulk requests"
            )

    def _check_bulk_limits(self, bulk_request: BulkRequest, payload: dict) -> None:
        """Refuse a bulk request exceeding the limits the server advertises.

        Those limits are defined at :rfc:`RFC7644 §3.7.4 <7644#section-3.7.4>`.
        """
        bulk = self._bulk_config
        if not bulk:
            return

        operations = bulk_request.operations or []
        if bulk.max_operations is not None and len(operations) > bulk.max_operations:
            raise InvalidValueException(
                detail=f"Bulk requests are limited to {bulk.max_operations} operations by the server"
            )

        if bulk.max_payload_size is None:
            return

        if len(json.dumps(payload).encode()) > bulk.max_payload_size:
            raise InvalidValueException(
                detail=f"Bulk request payloads are limited to {bulk.max_payload_size} bytes by the server"
            )

    def _prepare_bulk_request(
        self,
        bulk_request: BulkRequest | None = None,
        check_request_payload: bool | None = None,
        expected_status_codes: list[int] | None = None,
        **kwargs,
    ) -> RequestPayload:
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )

        if check_request_payload is None:
            check_request_payload = self.check_request_payload

        if bulk_request is None:
            raise InvalidValueException(detail="Missing bulk operations")

        self._check_bulk_support()

        if not check_request_payload:
            req.payload = bulk_request

        else:
            req.payload = bulk_request.model_dump(scim_ctx=Context.BULK_REQUEST)
            self._check_bulk_limits(bulk_request, req.payload)

        req.url = req.request_kwargs.pop("url", "/Bulk")
        req.expected_types = [BulkResponse[Union[self.resource_models]]]  # noqa: UP007
        return req

    def _prepare_delete_request(
        self,
        resource: Resource | type[Resource] | None = None,
        id: str | None = None,
        expected_status_codes: list[int] | None = None,
        **kwargs,
    ) -> RequestPayload:
        resource = self._resolve_deprecated_resource_model(resource, kwargs)
        resource_model, id, _instance = self._resolve_target(resource, id)
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )

        if resource_model is None:
            raise InvalidValueException(detail="No resource type to delete")

        self._check_resource_model(resource_model)
        if not id:
            raise InvalidValueException(detail="Resource must have an id")

        delete_url = self.resource_endpoint(resource_model) + f"/{id}"
        req.url = req.request_kwargs.pop("url", delete_url)
        self._set_if_match(req, _instance)
        return req

    def _prepare_replace_request(
        self,
        resource: Resource | dict,
        check_request_payload: bool | None = None,
        expected_status_codes: list[int] | None = None,
        **kwargs,
    ) -> RequestPayload:
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )

        if check_request_payload is None:
            check_request_payload = self.check_request_payload

        if not check_request_payload:
            req.payload = resource
            req.url = kwargs.pop("url", None)

        else:
            if isinstance(resource, Resource):
                resource_model = resource.__class__

            else:
                resource_model = get_model_by_payload(self.resource_models, resource)
                if not resource_model:
                    raise InvalidValueException(
                        detail="Cannot guess resource type from the payload"
                    )

                try:
                    resource = resource_model.model_validate(resource)
                except ValidationError as exc:
                    raise request_validation_exception(
                        exc, Context.RESOURCE_REPLACEMENT_REQUEST
                    ) from exc

            self._check_resource_model(resource_model)

            if not resource.id:
                raise InvalidValueException(detail="Resource must have an id")

            req.expected_types = [resource.__class__]
            req.payload = resource.model_dump(
                scim_ctx=Context.RESOURCE_REPLACEMENT_REQUEST
            )
            req.url = req.request_kwargs.pop(
                "url", self.resource_endpoint(resource.__class__) + f"/{resource.id}"
            )

        self._set_if_match(req, resource)
        return req

    def _prepare_patch_request(
        self,
        resource: ResourceT | type[ResourceT] | None = None,
        patch_op: PatchOp[ResourceT] | dict | str | None = None,
        id: str | None = None,
        check_request_payload: bool | None = None,
        expected_status_codes: list[int] | None = None,
        **kwargs,
    ) -> RequestPayload:
        """Prepare a PATCH request payload."""
        resource = self._resolve_deprecated_resource_model(resource, kwargs)
        patch_op, id = self._resolve_patch_arguments(patch_op, id)
        resource_model, id, _instance = self._resolve_target(resource, id)
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )

        if check_request_payload is None:
            check_request_payload = self.check_request_payload

        if resource_model is None:
            raise InvalidValueException(detail="No resource type to modify")

        self._check_resource_model(resource_model)
        if not id:
            raise InvalidValueException(detail="Resource must have an id")

        if patch_op is None:
            raise InvalidValueException(detail="Missing patch operation")

        if not check_request_payload:
            req.payload = patch_op
            req.url = req.request_kwargs.pop(
                "url", f"{self.resource_endpoint(resource_model)}/{id}"
            )

        else:
            if isinstance(patch_op, dict):
                req.payload = patch_op
            else:
                try:
                    req.payload = patch_op.model_dump(
                        scim_ctx=Context.RESOURCE_PATCH_REQUEST
                    )
                except ValidationError as exc:
                    raise request_validation_exception(
                        exc, Context.RESOURCE_PATCH_REQUEST
                    ) from exc

            req.url = req.request_kwargs.pop(
                "url", f"{self.resource_endpoint(resource_model)}/{id}"
            )

        req.expected_types = [resource_model]
        self._set_if_match(req, _instance)
        return req

    def modify(
        self,
        resource: ResourceT | type[ResourceT] | None = None,
        patch_op: PatchOp[ResourceT] | dict | None = None,
        id: str | None = None,
        **kwargs,
    ) -> ResourceT | Error | dict | None:
        raise NotImplementedError()

    def build_resource_models(
        self, resource_types: Collection[ResourceType], schemas: Collection[Schema]
    ) -> tuple[type[Resource]]:
        """Build models from server objects."""
        resource_types_by_schema = {
            resource_type.schema_: resource_type for resource_type in resource_types
        }
        schema_objs_by_schema = {schema_obj.id: schema_obj for schema_obj in schemas}

        resource_models = []
        for schema, resource_type in resource_types_by_schema.items():
            schema_obj = schema_objs_by_schema[schema]
            model = Resource.from_schema(schema_obj)
            extensions: tuple[type[Extension], ...] = ()
            for ext_schema in resource_type.schema_extensions or []:
                schema_obj = schema_objs_by_schema[ext_schema.schema_]
                extension = Extension.from_schema(schema_obj)
                extensions = extensions + (extension,)
            if extensions:
                model = model[Union[extensions]]  # noqa: UP007
            resource_models.append(model)

        return tuple(resource_models)


class BaseSyncSCIMClient(SCIMClient):
    """Base class for synchronous request clients."""

    def create(
        self,
        resource: AnyResource | dict,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.CREATION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> AnyResource | Error | dict:
        """Perform a POST request to create, as defined in :rfc:`RFC7644 §3.3 <7644#section-3.3>`.

        :param resource: The resource to create
            If is a :class:`dict`, the resource type will be guessed from the schema.
        :param check_request_payload: If set, overwrites :paramref:`~scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`~scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`~scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying HTTP request
            library.

        :return:
            - An :class:`~scim2_models.Error` object in case of error.
            - The created object as returned by the server in case of success and :code:`check_response_payload` is :data:`True`.
            - The created object payload as returned by the server in case of success and :code:`check_response_payload` is :data:`False`.

        .. code-block:: python
            :caption: Creation of a `User` resource

            from scim2_models import User

            request = User(user_name="bjensen@example.com")
            response = scim.create(request)
            # 'response' may be a User or an Error object

        .. tip::

            Check the :attr:`~scim2_models.Context.RESOURCE_CREATION_REQUEST`
            and :attr:`~scim2_models.Context.RESOURCE_CREATION_RESPONSE` contexts to understand
            which value will excluded from the request payload, and which values are expected in
            the response payload.
        """
        raise NotImplementedError()

    def query(
        self,
        target: type[Resource] | Resource | None = None,
        id: str | None = None,
        query_parameters: ResponseParameters | dict | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.QUERY_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        search_request: ResponseParameters | dict | None = None,
        **kwargs,
    ) -> Resource | ListResponse[Resource] | Error | dict:
        """Perform a GET request to read resources, as defined in :rfc:`RFC7644 §3.4.2 <7644#section-3.4.2>`.

        The resource to read can be designated either by a
        :class:`~scim2_models.Resource` object, or by a
        :class:`~scim2_models.Resource` subtype and an id.

        - If ``target`` is a :class:`~scim2_models.Resource` object, the resource
          with the same id will be reached. The object must have an id. When the
          server supports ETags and the object carries a version, the read is
          conditional, and the object itself is returned when the server answers
          with a ``304 Not Modified``.
        - If ``id`` is not :data:`None`, the resource with the exact id will be reached.
        - If ``target`` is a :class:`~scim2_models.Resource` subtype and ``id`` is
          :data:`None`, all the resources with the given type will be reached.
        - If ``target`` is :data:`None`, all the available resources will be reached.

        :param target: A :class:`~scim2_models.Resource` object, a
            :class:`~scim2_models.Resource` subtype, or :data:`None`
        :param id: The SCIM id of an object to get, or :data:`None`.
            It cannot be used together with a :class:`~scim2_models.Resource` object.
        :param query_parameters: A :class:`~scim2_models.ResponseParameters` or
            :class:`~scim2_models.SearchRequest` detailing the query parameters.
            Use :class:`~scim2_models.ResponseParameters` when querying a single
            resource by id, where only ``attributes`` and ``excludedAttributes``
            are meaningful (:rfc:`RFC 7644 §3.4.1 <7644#section-3.4.1>`).
            Use :class:`~scim2_models.SearchRequest` when listing resources, to
            also pass ``filter``, ``sortBy``, ``sortOrder``, ``startIndex`` and
            ``count`` (:rfc:`RFC 7644 §3.4.2 <7644#section-3.4.2>`).
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying HTTP request library.

        :return:
            - A :class:`~scim2_models.Error` object in case of error.
            - A `target` type object in case of success when a single resource is designated,
              which is the ``target`` object itself when the server answers ``304 Not Modified``.
            - A ``ListResponse[target]`` object in case of success otherwise.

        .. note::

            Querying a :class:`~scim2_models.ServiceProviderConfig` will return a
            single object, and not a :class:`~scim2_models.ListResponse`.

        :usage:

        .. code-block:: python
            :caption: Query of a `User` resource knowing its id

            from scim2_models import User

            response = scim.query(User, "my-user-id")
            response = scim.query(User(id="my-user-id"))
            # 'response' may be a User or an Error object

        .. code-block:: python
            :caption: Query of all the `User` resources filtering the ones with `userName` starts with `john`

            from scim2_models import User, SearchRequest

            req = SearchRequest(filter='userName sw "john"')
            response = scim.query(User, query_parameters=req)
            # 'response' may be a ListResponse[User] or an Error object

        .. code-block:: python
            :caption: Query of all the available resources

            from scim2_models import User

            response = scim.query()
            # 'response' may be a ListResponse[Union[User, Group, ...]] or an Error object

        .. tip::

            Check the :attr:`~scim2_models.Context.RESOURCE_QUERY_REQUEST`
            and :attr:`~scim2_models.Context.RESOURCE_QUERY_RESPONSE` contexts to understand
            which value will excluded from the request payload, and which values are expected in
            the response payload.
        """
        raise NotImplementedError()

    def search(
        self,
        search_request: SearchRequest | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.SEARCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> Resource | ListResponse[Resource] | Error | dict:
        """Perform a POST search request to read all available resources, as defined in :rfc:`RFC7644 §3.4.3 <7644#section-3.4.3>`.

        :param resource_models: Resource type or union of types expected
            to be read from the response.
        :param search_request: An object detailing the search query parameters.
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.

        :return:
            - A :class:`~scim2_models.Error` object in case of error.
            - A ``ListResponse[resource_model]`` object in case of success.

        :usage:

        .. code-block:: python
            :caption: Searching for all the resources filtering the ones with `id` contains with `admin`

            from scim2_models import User, SearchRequest

            req = SearchRequest(filter='id co "john"')
            response = scim.search(search_request=search_request)
            # 'response' may be a ListResponse[User] or an Error object

        .. tip::

            Check the :attr:`~scim2_models.Context.SEARCH_REQUEST`
            and :attr:`~scim2_models.Context.SEARCH_RESPONSE` contexts to understand
            which value will excluded from the request payload, and which values are expected in
            the response payload.
        """
        raise NotImplementedError()

    def bulk(
        self,
        bulk_request: BulkRequest | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = SCIMClient.BULK_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> BulkResponse | Error | dict:
        """Perform a POST bulk request to execute bulk operations, as defined in :rfc:`RFC7644 §3.7 <7644#section-3.7>`.

        :param bulk_request: An object detailing the bulk request.
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.

        :return:
            - A :class:`~scim2_models.Error` object in case of error.
            - A :class:`~scim2_models.BulkResponse` object in case of success.

        :usage:

        .. code-block:: python
            :caption: Simultaneously creating a `User` resource and a `Group` resource containing the user

            from scim2_models import (
                BulkRequest,
                BulkOperation,
                Group,
                GroupMember,
                User,
            )

            req = BulkRequest[User | Group](
                operations=[
                    BulkOperation[User](
                        method="POST",
                        path="/Users",
                        bulk_id="qwerty",
                        data=User(user_name="Alice"),
                    ),
                    BulkOperation[Group](
                        method="POST",
                        path="/Groups",
                        bulk_id="ytrewq",
                        data=Group(
                            display_name="Tour Guides",
                            members=[GroupMember(type="User", value="bulkId:qwerty")],
                        ),
                    ),
                ]
            )
            response = scim.bulk(req)
            # 'response' may be a BulkResponse or an Error object

        .. tip::

            Check the :attr:`~scim2_models.Context.BULK_REQUEST`
            and :attr:`~scim2_models.Context.BULK_RESPONSE` contexts to understand
            which values will be excluded from the request payload, and which values are expected in
            the response payload.

        .. tip::

            When the :class:`~scim2_models.ServiceProviderConfig` is known, the request is
            checked against the bulk capabilities the server advertises, and a request the
            server would answer with a ``413`` is not sent.
        """
        raise NotImplementedError()

    def delete(
        self,
        resource: Resource | type[Resource] | None = None,
        id: str | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.DELETION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> Error | dict | None:
        """Perform a DELETE request, as defined in :rfc:`RFC7644 §3.6 <7644#section-3.6>`.

        The resource to delete can be designated either by a
        :class:`~scim2_models.Resource` object, or by a
        :class:`~scim2_models.Resource` subtype and an id.

        :param resource: The resource to delete, or its type.
        :param id: The id of the resource to delete, when a type is passed.
            It cannot be used together with a :class:`~scim2_models.Resource` object.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.

        :return:
            - A :class:`~scim2_models.Error` object in case of error.
            - :data:`None` in case of success.

        :usage:

        .. code-block:: python
            :caption: Deleting an `User` which `id` is `foobar`

            from scim2_models import User

            response = scim.delete(User, "foobar")

            user = scim.query(User, "foobar")
            response = scim.delete(user)
            # 'response' may be None, or an Error object
        """
        raise NotImplementedError()

    def replace(
        self,
        resource: AnyResource | dict,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.REPLACEMENT_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> AnyResource | Error | dict:
        """Perform a PUT request to replace a resource, as defined in :rfc:`RFC7644 §3.5.1 <7644#section-3.5.1>`.

        :param resource: The new resource to replace.
            If is a :class:`dict`, the resource type will be guessed from the schema.
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.

        :return:
            - An :class:`~scim2_models.Error` object in case of error.
            - The updated object as returned by the server in case of success.

        :usage:

        .. code-block:: python
            :caption: Replacement of a `User` resource

            from scim2_models import User

            user = scim.query(User, "my-used-id")
            user.display_name = "Fancy New Name"
            updated_user = scim.replace(user)

        .. tip::

            Check the :attr:`~scim2_models.Context.RESOURCE_REPLACEMENT_REQUEST`
            and :attr:`~scim2_models.Context.RESOURCE_REPLACEMENT_RESPONSE` contexts to understand
            which value will excluded from the request payload, and which values are expected in
            the response payload.
        """
        raise NotImplementedError()

    def modify(
        self,
        resource: ResourceT | type[ResourceT] | None = None,
        patch_op: PatchOp[ResourceT] | dict | None = None,
        id: str | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.PATCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> ResourceT | Error | dict | None:
        """Perform a PATCH request to modify a resource, as defined in :rfc:`RFC7644 §3.5.2 <7644#section-3.5.2>`.

        The resource to modify can be designated either by a
        :class:`~scim2_models.Resource` object, or by a
        :class:`~scim2_models.Resource` subtype and an id.

        :param resource: The resource to modify, or its type.
        :param patch_op: The :class:`~scim2_models.PatchOp` object describing the modifications.
            Must be parameterized with the same resource type as ``resource``
            (e.g., :code:`PatchOp[User]` when ``resource`` is :code:`User`).
        :param id: The id of the resource to modify, when a type is passed.
            It cannot be used together with a :class:`~scim2_models.Resource` object.
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.

        :return:
            - An :class:`~scim2_models.Error` object in case of error.
            - The updated object as returned by the server in case of success if status code is 200.
            - :data:`None` in case of success if status code is 204.

        :usage:

        .. code-block:: python
            :caption: Modification of a `User` resource

            from scim2_models import User, PatchOp, PatchOperation

            operation = PatchOperation(
                op="replace", path="displayName", value="New Display Name"
            )
            patch_op = PatchOp[User](operations=[operation])
            response = scim.modify(User, "my-user-id", patch_op)

            user = scim.query(User, "my-user-id")
            response = scim.modify(user, patch_op)
            # 'response' may be a User, None, or an Error object

        .. tip::

            Check the :attr:`~scim2_models.Context.RESOURCE_PATCH_REQUEST`
            and :attr:`~scim2_models.Context.RESOURCE_PATCH_RESPONSE` contexts to understand
            which value will excluded from the request payload, and which values are expected in
            the response payload.
        """
        raise NotImplementedError()

    def discover(self, schemas=True, resource_types=True, service_provider_config=True):
        """Dynamically discover the server configuration objects.

        :param schemas: Whether to discover the :class:`~scim2_models.Schema` endpoint.
        :param resource_types: Whether to discover the :class:`~scim2_models.ResourceType` endpoint.
        :param service_provider_config: Whether to discover the :class:`~scim2_models.ServiceProviderConfig` endpoint.
        """
        if resource_types:
            resource_types_response = self.query(ResourceType)
            self.resource_types = resource_types_response.resources

        if schemas:
            schemas_response = self.query(Schema)
            self.resource_models = self.build_resource_models(
                self.resource_types, schemas_response.resources
            )

        if service_provider_config:
            self.service_provider_config = self.query(ServiceProviderConfig)


class BaseAsyncSCIMClient(SCIMClient):
    """Base class for asynchronous request clients."""

    async def create(
        self,
        resource: AnyResource | dict,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.CREATION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> AnyResource | Error | dict:
        """Perform a POST request to create, as defined in :rfc:`RFC7644 §3.3 <7644#section-3.3>`.

        :param resource: The resource to create
            If is a :class:`dict`, the resource type will be guessed from the schema.
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying HTTP request
            library.

        :return:
            - An :class:`~scim2_models.Error` object in case of error.
            - The created object as returned by the server in case of success and :code:`check_response_payload` is :data:`True`.
            - The created object payload as returned by the server in case of success and :code:`check_response_payload` is :data:`False`.

        .. code-block:: python
            :caption: Creation of a `User` resource

            from scim2_models import User

            request = User(user_name="bjensen@example.com")
            response = scim.create(request)
            # 'response' may be a User or an Error object

        .. tip::

            Check the :attr:`~scim2_models.Context.RESOURCE_CREATION_REQUEST`
            and :attr:`~scim2_models.Context.RESOURCE_CREATION_RESPONSE` contexts to understand
            which value will excluded from the request payload, and which values are expected in
            the response payload.
        """
        raise NotImplementedError()

    async def query(
        self,
        target: type[Resource] | Resource | None = None,
        id: str | None = None,
        query_parameters: ResponseParameters | dict | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.QUERY_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        search_request: ResponseParameters | dict | None = None,
        **kwargs,
    ) -> Resource | ListResponse[Resource] | Error | dict:
        """Perform a GET request to read resources, as defined in :rfc:`RFC7644 §3.4.2 <7644#section-3.4.2>`.

        The resource to read can be designated either by a
        :class:`~scim2_models.Resource` object, or by a
        :class:`~scim2_models.Resource` subtype and an id.

        - If ``target`` is a :class:`~scim2_models.Resource` object, the resource
          with the same id will be reached. The object must have an id. When the
          server supports ETags and the object carries a version, the read is
          conditional, and the object itself is returned when the server answers
          with a ``304 Not Modified``.
        - If ``id`` is not :data:`None`, the resource with the exact id will be reached.
        - If ``target`` is a :class:`~scim2_models.Resource` subtype and ``id`` is
          :data:`None`, all the resources with the given type will be reached.
        - If ``target`` is :data:`None`, all the available resources will be reached.

        :param target: A :class:`~scim2_models.Resource` object, a
            :class:`~scim2_models.Resource` subtype, or :data:`None`
        :param id: The SCIM id of an object to get, or :data:`None`.
            It cannot be used together with a :class:`~scim2_models.Resource` object.
        :param query_parameters: A :class:`~scim2_models.ResponseParameters` or
            :class:`~scim2_models.SearchRequest` detailing the query parameters.
            Use :class:`~scim2_models.ResponseParameters` when querying a single
            resource by id, where only ``attributes`` and ``excludedAttributes``
            are meaningful (:rfc:`RFC 7644 §3.4.1 <7644#section-3.4.1>`).
            Use :class:`~scim2_models.SearchRequest` when listing resources, to
            also pass ``filter``, ``sortBy``, ``sortOrder``, ``startIndex`` and
            ``count`` (:rfc:`RFC 7644 §3.4.2 <7644#section-3.4.2>`).
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying HTTP request library.

        :return:
            - A :class:`~scim2_models.Error` object in case of error.
            - A `target` type object in case of success when a single resource is designated,
              which is the ``target`` object itself when the server answers ``304 Not Modified``.
            - A ``ListResponse[target]`` object in case of success otherwise.

        .. note::

            Querying a :class:`~scim2_models.ServiceProviderConfig` will return a
            single object, and not a :class:`~scim2_models.ListResponse`.

        :usage:

        .. code-block:: python
            :caption: Query of a `User` resource knowing its id

            from scim2_models import User

            response = scim.query(User, "my-user-id")
            response = scim.query(User(id="my-user-id"))
            # 'response' may be a User or an Error object

        .. code-block:: python
            :caption: Query of all the `User` resources filtering the ones with `userName` starts with `john`

            from scim2_models import User, SearchRequest

            req = SearchRequest(filter='userName sw "john"')
            response = scim.query(User, query_parameters=req)
            # 'response' may be a ListResponse[User] or an Error object

        .. code-block:: python
            :caption: Query of all the available resources

            from scim2_models import User

            response = scim.query()
            # 'response' may be a ListResponse[Union[User, Group, ...]] or an Error object

        .. tip::

            Check the :attr:`~scim2_models.Context.RESOURCE_QUERY_REQUEST`
            and :attr:`~scim2_models.Context.RESOURCE_QUERY_RESPONSE` contexts to understand
            which value will excluded from the request payload, and which values are expected in
            the response payload.
        """
        raise NotImplementedError()

    async def search(
        self,
        search_request: SearchRequest | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.SEARCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> Resource | ListResponse[Resource] | Error | dict:
        """Perform a POST search request to read all available resources, as defined in :rfc:`RFC7644 §3.4.3 <7644#section-3.4.3>`.

        :param resource_models: Resource type or union of types expected
            to be read from the response.
        :param search_request: An object detailing the search query parameters.
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.

        :return:
            - A :class:`~scim2_models.Error` object in case of error.
            - A ``ListResponse[resource_model]`` object in case of success.

        :usage:

        .. code-block:: python
            :caption: Searching for all the resources filtering the ones with `id` contains with `admin`

            from scim2_models import User, SearchRequest

            req = SearchRequest(filter='id co "john"')
            response = scim.search(search_request=search_request)
            # 'response' may be a ListResponse[User] or an Error object

        .. tip::

            Check the :attr:`~scim2_models.Context.SEARCH_REQUEST`
            and :attr:`~scim2_models.Context.SEARCH_RESPONSE` contexts to understand
            which value will excluded from the request payload, and which values are expected in
            the response payload.
        """
        raise NotImplementedError()

    async def bulk(
        self,
        bulk_request: BulkRequest | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = SCIMClient.BULK_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> BulkResponse | Error | dict:
        """Perform a POST bulk request to execute bulk operations, as defined in :rfc:`RFC7644 §3.7 <7644#section-3.7>`.

        :param bulk_request: An object detailing the bulk request.
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.

        :return:
            - A :class:`~scim2_models.Error` object in case of error.
            - A :class:`~scim2_models.BulkResponse` object in case of success.

        :usage:

        .. code-block:: python
            :caption: Simultaneously creating a `User` resource and a `Group` resource containing the user

            from scim2_models import (
                BulkRequest,
                BulkOperation,
                Group,
                GroupMember,
                User,
            )

            req = BulkRequest[User | Group](
                operations=[
                    BulkOperation[User](
                        method="POST",
                        path="/Users",
                        bulk_id="qwerty",
                        data=User(user_name="Alice"),
                    ),
                    BulkOperation[Group](
                        method="POST",
                        path="/Groups",
                        bulk_id="ytrewq",
                        data=Group(
                            display_name="Tour Guides",
                            members=[GroupMember(type="User", value="bulkId:qwerty")],
                        ),
                    ),
                ]
            )
            response = scim.bulk(req)
            # 'response' may be a BulkResponse or an Error object

        .. tip::

            Check the :attr:`~scim2_models.Context.BULK_REQUEST`
            and :attr:`~scim2_models.Context.BULK_RESPONSE` contexts to understand
            which values will be excluded from the request payload, and which values are expected in
            the response payload.

        .. tip::

            When the :class:`~scim2_models.ServiceProviderConfig` is known, the request is
            checked against the bulk capabilities the server advertises, and a request the
            server would answer with a ``413`` is not sent.
        """
        raise NotImplementedError()

    async def delete(
        self,
        resource: Resource | type[Resource] | None = None,
        id: str | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.DELETION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> Error | dict | None:
        """Perform a DELETE request, as defined in :rfc:`RFC7644 §3.6 <7644#section-3.6>`.

        The resource to delete can be designated either by a
        :class:`~scim2_models.Resource` object, or by a
        :class:`~scim2_models.Resource` subtype and an id.

        :param resource: The resource to delete, or its type.
        :param id: The id of the resource to delete, when a type is passed.
            It cannot be used together with a :class:`~scim2_models.Resource` object.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.

        :return:
            - A :class:`~scim2_models.Error` object in case of error.
            - :data:`None` in case of success.

        :usage:

        .. code-block:: python
            :caption: Deleting an `User` which `id` is `foobar`

            from scim2_models import User

            response = await scim.delete(User, "foobar")

            user = await scim.query(User, "foobar")
            response = await scim.delete(user)
            # 'response' may be None, or an Error object
        """
        raise NotImplementedError()

    async def replace(
        self,
        resource: AnyResource | dict,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.REPLACEMENT_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> AnyResource | Error | dict:
        """Perform a PUT request to replace a resource, as defined in :rfc:`RFC7644 §3.5.1 <7644#section-3.5.1>`.

        :param resource: The new resource to replace.
            If is a :class:`dict`, the resource type will be guessed from the schema.
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.

        :return:
            - An :class:`~scim2_models.Error` object in case of error.
            - The updated object as returned by the server in case of success.

        :usage:

        .. code-block:: python
            :caption: Replacement of a `User` resource

            from scim2_models import User

            user = scim.query(User, "my-used-id")
            user.display_name = "Fancy New Name"
            updated_user = scim.replace(user)

        .. tip::

            Check the :attr:`~scim2_models.Context.RESOURCE_REPLACEMENT_REQUEST`
            and :attr:`~scim2_models.Context.RESOURCE_REPLACEMENT_RESPONSE` contexts to understand
            which value will excluded from the request payload, and which values are expected in
            the response payload.
        """
        raise NotImplementedError()

    async def modify(
        self,
        resource: ResourceT | type[ResourceT] | None = None,
        patch_op: PatchOp[ResourceT] | dict | None = None,
        id: str | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.PATCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs,
    ) -> ResourceT | Error | dict | None:
        """Perform a PATCH request to modify a resource, as defined in :rfc:`RFC7644 §3.5.2 <7644#section-3.5.2>`.

        The resource to modify can be designated either by a
        :class:`~scim2_models.Resource` object, or by a
        :class:`~scim2_models.Resource` subtype and an id.

        :param resource: The resource to modify, or its type.
        :param patch_op: The :class:`~scim2_models.PatchOp` object describing the modifications.
            Must be parameterized with the same resource type as ``resource``
            (e.g., :code:`PatchOp[User]` when ``resource`` is :code:`User`).
        :param id: The id of the resource to modify, when a type is passed.
            It cannot be used together with a :class:`~scim2_models.Resource` object.
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.

        :return:
            - An :class:`~scim2_models.Error` object in case of error.
            - The updated object as returned by the server in case of success if status code is 200.
            - :data:`None` in case of success if status code is 204.

        :usage:

        .. code-block:: python
            :caption: Modification of a `User` resource

            from scim2_models import User, PatchOp, PatchOperation

            operation = PatchOperation(
                op="replace", path="displayName", value="New Display Name"
            )
            patch_op = PatchOp[User](operations=[operation])
            response = await scim.modify(User, "my-user-id", patch_op)

            user = await scim.query(User, "my-user-id")
            response = await scim.modify(user, patch_op)
            # 'response' may be a User, None, or an Error object

        .. tip::

            Check the :attr:`~scim2_models.Context.RESOURCE_PATCH_REQUEST`
            and :attr:`~scim2_models.Context.RESOURCE_PATCH_RESPONSE` contexts to understand
            which value will excluded from the request payload, and which values are expected in
            the response payload.
        """
        raise NotImplementedError()

    async def discover(
        self, schemas=True, resource_types=True, service_provider_config=True
    ):
        """Dynamically discover the server configuration objects.

        :param schemas: Whether to discover the :class:`~scim2_models.Schema` endpoint.
        :param resource_types: Whether to discover the :class:`~scim2_models.ResourceType` endpoint.
        :param service_provider_config: Whether to discover the :class:`~scim2_models.ServiceProviderConfig` endpoint.
        """
        if schemas:
            schemas_task = asyncio.create_task(self.query(Schema))

        if resource_types:
            resources_types_task = asyncio.create_task(self.query(ResourceType))

        if service_provider_config:
            spc_task = asyncio.create_task(self.query(ServiceProviderConfig))

        if resource_types:
            resource_types_response = await resources_types_task
            self.resource_types = resource_types_response.resources

        if schemas:
            schemas_response = await schemas_task
            self.resource_models = self.build_resource_models(
                self.resource_types, schemas_response.resources
            )

        if service_provider_config:
            self.service_provider_config = await spc_task
