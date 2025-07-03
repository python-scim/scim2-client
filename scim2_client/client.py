import asyncio
import sys
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any
from typing import Optional
from typing import Union

from pydantic import ValidationError
from scim2_models import AnyResource
from scim2_models import Context
from scim2_models import Error
from scim2_models import Extension
from scim2_models import ListResponse
from scim2_models import PatchOp
from scim2_models import Resource
from scim2_models import ResourceType
from scim2_models import Schema
from scim2_models import SearchRequest
from scim2_models import ServiceProviderConfig

from scim2_client.errors import RequestPayloadValidationError
from scim2_client.errors import ResponsePayloadValidationError
from scim2_client.errors import SCIMClientError
from scim2_client.errors import SCIMRequestError
from scim2_client.errors import SCIMResponseError
from scim2_client.errors import SCIMResponseErrorObject
from scim2_client.errors import UnexpectedContentType
from scim2_client.errors import UnexpectedStatusCode

BASE_HEADERS = {
    "Accept": "application/scim+json",
    "Content-Type": "application/scim+json",
}
CONFIG_RESOURCES = (ResourceType, Schema, ServiceProviderConfig)


@dataclass
class RequestPayload:
    request_kwargs: dict
    url: Optional[str] = None
    payload: Optional[dict] = None
    expected_types: Optional[list[type[Resource]]] = None
    expected_status_codes: Optional[list[int]] = None


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
        :class:`~scim2_models.Error` object during a request, a :class:`~scim2_client.SCIMResponseErrorObject`
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

    QUERY_RESPONSE_STATUS_CODES: list[int] = [200, 400, 307, 308, 401, 403, 404, 500]
    """Resource querying HTTP codes.

    As defined at :rfc:`RFC7644 §3.4.2 <7644#section-3.4.2>` and
    :rfc:`RFC7644 §3.12 <7644#section-3.12>`.
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

    DELETION_RESPONSE_STATUS_CODES: list[int] = [
        204,
        307,
        308,
        400,
        401,
        403,
        404,
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

    def __init__(
        self,
        resource_models: Optional[Collection[type[Resource]]] = None,
        resource_types: Optional[Collection[ResourceType]] = None,
        service_provider_config: Optional[ServiceProviderConfig] = None,
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

    def get_resource_model(self, name: str) -> Optional[type[Resource]]:
        """Get a registered model by its name or its schema."""
        for resource_model in self.resource_models:
            schema = resource_model.model_fields["schemas"].default[0]
            if schema == name or schema.split(":")[-1] == name:
                return resource_model
        return None

    def check_resource_model(
        self, resource_model: type[Resource], payload=None
    ) -> None:
        # We need to check the actual schema names, comapring the class
        # types does not work because if the resource_models are
        # discovered. The classes might differ:
        #   <class 'scim2_models.rfc7643.user.User'> vs <class 'scim2_models.rfc7643.schema.User'>
        schema_to_check = resource_model.model_fields["schemas"].default[0]
        for element in self.resource_models:
            schema = element.model_fields["schemas"].default[0]
            if schema_to_check == schema:
                return

        if (
            resource_model not in CONFIG_RESOURCES
        ):
            raise SCIMRequestError(
                f"Unknown resource type: '{resource_model}'", source=payload
            )

    def resource_endpoint(self, resource_model: Optional[type[Resource]]) -> str:
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

        schema = resource_model.model_fields["schemas"].default[0]
        for resource_type in self.resource_types or []:
            if schema == resource_type.schema_:
                return resource_type.endpoint

        raise SCIMRequestError(f"No ResourceType is matching the schema: {schema}")

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
        self, status_code: int, expected_status_codes: Optional[list[int]]
    ):
        if (
            self.check_response_status_codes
            and expected_status_codes
            and status_code not in expected_status_codes
        ):
            raise UnexpectedStatusCode(status_code)

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
            raise UnexpectedContentType(content_type=actual_content_type)

    def check_response(
        self,
        payload: Optional[dict],
        status_code: int,
        headers: dict,
        expected_status_codes: Optional[list[int]] = None,
        expected_types: Optional[list[type[Resource]]] = None,
        check_response_payload: Optional[bool] = None,
        raise_scim_errors: Optional[bool] = None,
        scim_ctx: Optional[Context] = None,
    ) -> Union[Error, None, dict, type[Resource]]:
        if raise_scim_errors is None:
            raise_scim_errors = self.raise_scim_errors

        self._check_content_types(headers)

        # In addition to returning an HTTP response code, implementers MUST return
        # the errors in the body of the response in a JSON format
        # https://datatracker.ietf.org/doc/html/rfc7644.html#section-3.12

        no_content_status_codes = [204, 205]
        if status_code in no_content_status_codes:
            response_payload = None

        else:
            response_payload = payload

        if check_response_payload is None:
            check_response_payload = self.check_response_payload

        if not check_response_payload:
            self._check_status_codes(status_code, expected_status_codes)
            return response_payload

        if (
            response_payload
            and response_payload.get("schemas") == Error.model_fields["schemas"].default
        ):
            error = Error.model_validate(response_payload)
            if raise_scim_errors:
                raise SCIMResponseErrorObject(obj=error.detail, source=error)
            return error

        self._check_status_codes(status_code, expected_status_codes)

        if not expected_types:
            return response_payload

        actual_type = Resource.get_by_payload(
            expected_types, response_payload, with_extensions=False
        )

        if response_payload and not actual_type:
            expected = ", ".join([type_.__name__ for type_ in expected_types])
            try:
                schema = ", ".join(response_payload["schemas"])
                message = f"Expected type {expected} but got unknown resource with schemas: {schema}"
            except KeyError:
                message = (
                    f"Expected type {expected} but got undefined object with no schema"
                )

            raise SCIMResponseError(message)

        try:
            return actual_type.model_validate(response_payload, scim_ctx=scim_ctx)
        except ValidationError as exc:
            scim_exc = ResponsePayloadValidationError()
            if sys.version_info >= (3, 11):  # pragma: no cover
                scim_exc.add_note(str(exc))
            raise scim_exc from exc

    def prepare_create_request(
        self,
        resource: Union[AnyResource, dict],
        check_request_payload: Optional[bool] = None,
        expected_status_codes: Optional[list[int]] = None,
        raise_scim_errors: Optional[bool] = None,
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
                resource_model = Resource.get_by_payload(self.resource_models, resource)
                if not resource_model:
                    raise SCIMRequestError(
                        "Cannot guess resource type from the payload"
                    )

                try:
                    resource = resource_model.model_validate(resource)
                except ValidationError as exc:
                    scim_validation_exc = RequestPayloadValidationError(source=resource)
                    if sys.version_info >= (3, 11):  # pragma: no cover
                        scim_validation_exc.add_note(str(exc))
                    raise scim_validation_exc from exc

            self.check_resource_model(resource_model, resource)
            req.expected_types = [resource.__class__]
            req.url = req.request_kwargs.pop(
                "url", self.resource_endpoint(resource_model)
            )
            req.payload = resource.model_dump(
                scim_ctx=Context.RESOURCE_CREATION_REQUEST
            )

        return req

    def prepare_query_request(
        self,
        resource_model: Optional[type[Resource]] = None,
        id: Optional[str] = None,
        search_request: Optional[Union[SearchRequest, dict]] = None,
        check_request_payload: Optional[bool] = None,
        expected_status_codes: Optional[list[int]] = None,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> RequestPayload:
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )

        if check_request_payload is None:
            check_request_payload = self.check_request_payload

        if resource_model and check_request_payload:
            self.check_resource_model(resource_model)

        payload: Optional[SearchRequest]
        if not check_request_payload:
            payload = search_request

        elif isinstance(search_request, SearchRequest):
            payload = search_request.model_dump(
                exclude_unset=True,
                scim_ctx=Context.RESOURCE_QUERY_REQUEST,
            )

        else:
            payload = None

        req.payload = payload
        req.url = req.request_kwargs.pop("url", self.resource_endpoint(resource_model))

        if resource_model is None:
            req.expected_types = [
                *self.resource_models,
                ListResponse[Union[self.resource_models]],
            ]

        elif resource_model == ServiceProviderConfig:
            req.expected_types = [resource_model]
            if id:
                raise SCIMClientError("ServiceProviderConfig cannot have an id")

        elif id:
            req.expected_types = [resource_model]
            req.url = f"{req.url}/{id}"

        else:
            req.expected_types = [ListResponse[resource_model]]

        return req

    def prepare_search_request(
        self,
        search_request: Optional[SearchRequest] = None,
        check_request_payload: Optional[bool] = None,
        expected_status_codes: Optional[list[int]] = None,
        raise_scim_errors: Optional[bool] = None,
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
        req.expected_types = [ListResponse[Union[self.resource_models]]]
        return req

    def prepare_delete_request(
        self,
        resource_model: type,
        id: str,
        expected_status_codes: Optional[list[int]] = None,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> RequestPayload:
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )

        self.check_resource_model(resource_model)
        delete_url = self.resource_endpoint(resource_model) + f"/{id}"
        req.url = req.request_kwargs.pop("url", delete_url)
        return req

    def prepare_replace_request(
        self,
        resource: Union[AnyResource, dict],
        check_request_payload: Optional[bool] = None,
        expected_status_codes: Optional[list[int]] = None,
        raise_scim_errors: Optional[bool] = None,
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
                resource_model = Resource.get_by_payload(self.resource_models, resource)
                if not resource_model:
                    raise SCIMRequestError(
                        "Cannot guess resource type from the payload",
                        source=resource,
                    )

                try:
                    resource = resource_model.model_validate(resource)
                except ValidationError as exc:
                    scim_validation_exc = RequestPayloadValidationError(source=resource)
                    if sys.version_info >= (3, 11):  # pragma: no cover
                        scim_validation_exc.add_note(str(exc))
                    raise scim_validation_exc from exc

            self.check_resource_model(resource_model, resource)

            if not resource.id:
                raise SCIMRequestError("Resource must have an id", source=resource)

            req.expected_types = [resource.__class__]
            req.payload = resource.model_dump(
                scim_ctx=Context.RESOURCE_REPLACEMENT_REQUEST
            )
            req.url = req.request_kwargs.pop(
                "url", self.resource_endpoint(resource.__class__) + f"/{resource.id}"
            )

        return req

    def modify(
        self, resource: Union[AnyResource, dict], op: PatchOp, **kwargs
    ) -> Optional[Union[AnyResource, dict]]:
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
            extensions: tuple[Any, ...] = ()
            for ext_schema in resource_type.schema_extensions or []:
                schema_obj = schema_objs_by_schema[ext_schema.schema_]
                extension = Extension.from_schema(schema_obj)
                extensions = extensions + (extension,)
            if extensions:
                model = model[Union[extensions]]
            resource_models.append(model)

        return tuple(resource_models)


class BaseSyncSCIMClient(SCIMClient):
    """Base class for synchronous request clients."""

    def create(
        self,
        resource: Union[AnyResource, dict],
        check_request_payload: Optional[bool] = None,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = SCIMClient.CREATION_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Union[AnyResource, Error, dict]:
        """Perform a POST request to create, as defined in :rfc:`RFC7644 §3.3 <7644#section-3.3>`.

        :param resource: The resource to create
            If is a :data:`dict`, the resource type will be guessed from the schema.
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
        resource_model: Optional[type[Resource]] = None,
        id: Optional[str] = None,
        search_request: Optional[Union[SearchRequest, dict]] = None,
        check_request_payload: Optional[bool] = None,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = SCIMClient.QUERY_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Union[AnyResource, ListResponse[AnyResource], Error, dict]:
        """Perform a GET request to read resources, as defined in :rfc:`RFC7644 §3.4.2 <7644#section-3.4.2>`.

        - If `id` is not :data:`None`, the resource with the exact id will be reached.
        - If `id` is :data:`None`, all the resources with the given type will be reached.

        :param resource_model: A :class:`~scim2_models.Resource` subtype or :data:`None`
        :param id: The SCIM id of an object to get, or :data:`None`
        :param search_request: An object detailing the search query parameters.
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying HTTP request library.

        :return:
            - A :class:`~scim2_models.Error` object in case of error.
            - A `resource_model` object in case of success if `id` is not :data:`None`
            - A :class:`~scim2_models.ListResponse[resource_model]` object in case of success if `id` is :data:`None`

        .. note::

            Querying a :class:`~scim2_models.ServiceProviderConfig` will return a
            single object, and not a :class:`~scim2_models.ListResponse`.

        :usage:

        .. code-block:: python
            :caption: Query of a `User` resource knowing its id

            from scim2_models import User

            response = scim.query(User, "my-user-id)
            # 'response' may be a User or an Error object

        .. code-block:: python
            :caption: Query of all the `User` resources filtering the ones with `userName` starts with `john`

            from scim2_models import User, SearchRequest

            req = SearchRequest(filter='userName sw "john"')
            response = scim.query(User, search_request=search_request)
            # 'response' may be a ListResponse[User] or an Error object

        .. code-block:: python
            :caption: Query of all the available resources

            from scim2_models import User, SearchRequest

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
        search_request: Optional[SearchRequest] = None,
        check_request_payload: Optional[bool] = None,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = SCIMClient.SEARCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Union[AnyResource, ListResponse[AnyResource], Error, dict]:
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
            - A :class:`~scim2_models.ListResponse[resource_model]` object in case of success.

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

    def delete(
        self,
        resource_model: type,
        id: str,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = SCIMClient.DELETION_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Optional[Union[Error, dict]]:
        """Perform a DELETE request to create, as defined in :rfc:`RFC7644 §3.6 <7644#section-3.6>`.

        :param resource_model: The type of the resource to delete.
        :param id: The type id the resource to delete.
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

            from scim2_models import User, SearchRequest

            response = scim.delete(User, "foobar")
            # 'response' may be None, or an Error object
        """
        raise NotImplementedError()

    def replace(
        self,
        resource: Union[AnyResource, dict],
        check_request_payload: Optional[bool] = None,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = SCIMClient.REPLACEMENT_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Union[AnyResource, Error, dict]:
        """Perform a PUT request to replace a resource, as defined in :rfc:`RFC7644 §3.5.1 <7644#section-3.5.1>`.

        :param resource: The new resource to replace.
            If is a :data:`dict`, the resource type will be guessed from the schema.
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
        resource: Union[AnyResource, dict],
        check_request_payload: Optional[bool] = None,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = SCIMClient.CREATION_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Union[AnyResource, Error, dict]:
        """Perform a POST request to create, as defined in :rfc:`RFC7644 §3.3 <7644#section-3.3>`.

        :param resource: The resource to create
            If is a :data:`dict`, the resource type will be guessed from the schema.
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
        resource_model: Optional[type[Resource]] = None,
        id: Optional[str] = None,
        search_request: Optional[Union[SearchRequest, dict]] = None,
        check_request_payload: Optional[bool] = None,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = SCIMClient.QUERY_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Union[AnyResource, ListResponse[AnyResource], Error, dict]:
        """Perform a GET request to read resources, as defined in :rfc:`RFC7644 §3.4.2 <7644#section-3.4.2>`.

        - If `id` is not :data:`None`, the resource with the exact id will be reached.
        - If `id` is :data:`None`, all the resources with the given type will be reached.

        :param resource_model: A :class:`~scim2_models.Resource` subtype or :data:`None`
        :param id: The SCIM id of an object to get, or :data:`None`
        :param search_request: An object detailing the search query parameters.
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying HTTP request library.

        :return:
            - A :class:`~scim2_models.Error` object in case of error.
            - A `resource_model` object in case of success if `id` is not :data:`None`
            - A :class:`~scim2_models.ListResponse[resource_model]` object in case of success if `id` is :data:`None`

        .. note::

            Querying a :class:`~scim2_models.ServiceProviderConfig` will return a
            single object, and not a :class:`~scim2_models.ListResponse`.

        :usage:

        .. code-block:: python
            :caption: Query of a `User` resource knowing its id

            from scim2_models import User

            response = scim.query(User, "my-user-id)
            # 'response' may be a User or an Error object

        .. code-block:: python
            :caption: Query of all the `User` resources filtering the ones with `userName` starts with `john`

            from scim2_models import User, SearchRequest

            req = SearchRequest(filter='userName sw "john"')
            response = scim.query(User, search_request=search_request)
            # 'response' may be a ListResponse[User] or an Error object

        .. code-block:: python
            :caption: Query of all the available resources

            from scim2_models import User, SearchRequest

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
        search_request: Optional[SearchRequest] = None,
        check_request_payload: Optional[bool] = None,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = SCIMClient.SEARCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Union[AnyResource, ListResponse[AnyResource], Error, dict]:
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
            - A :class:`~scim2_models.ListResponse[resource_model]` object in case of success.

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

    async def delete(
        self,
        resource_model: type,
        id: str,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = SCIMClient.DELETION_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Optional[Union[Error, dict]]:
        """Perform a DELETE request to create, as defined in :rfc:`RFC7644 §3.6 <7644#section-3.6>`.

        :param resource_model: The type of the resource to delete.
        :param id: The type id the resource to delete.
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

            from scim2_models import User, SearchRequest

            response = scim.delete(User, "foobar")
            # 'response' may be None, or an Error object
        """
        raise NotImplementedError()

    async def replace(
        self,
        resource: Union[AnyResource, dict],
        check_request_payload: Optional[bool] = None,
        check_response_payload: Optional[bool] = None,
        expected_status_codes: Optional[
            list[int]
        ] = SCIMClient.REPLACEMENT_RESPONSE_STATUS_CODES,
        raise_scim_errors: Optional[bool] = None,
        **kwargs,
    ) -> Union[AnyResource, Error, dict]:
        """Perform a PUT request to replace a resource, as defined in :rfc:`RFC7644 §3.5.1 <7644#section-3.5.1>`.

        :param resource: The new resource to replace.
            If is a :data:`dict`, the resource type will be guessed from the schema.
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
