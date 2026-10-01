import asyncio
import json
import os
import sys
import warnings
from collections.abc import Awaitable
from collections.abc import Callable
from collections.abc import Collection
from collections.abc import Sequence
from dataclasses import dataclass
from functools import wraps
from typing import Any
from typing import Protocol
from typing import TypeVar
from typing import Union
from typing import cast
from typing import overload
from urllib.parse import quote
from urllib.parse import urlsplit

from pydantic import ValidationError
from scim2_models import AnyResource
from scim2_models import Bulk
from scim2_models import BulkRequest
from scim2_models import BulkResponse
from scim2_models import Context
from scim2_models import DescribedModel
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
from scim2_models import SCIMException
from scim2_models import ScimObject
from scim2_models import ScimProvider
from scim2_models import ScimProviderError
from scim2_models import SearchRequest
from scim2_models import ServiceProviderConfig
from scim2_models import get_model_by_payload

from scim2_client.errors import InvalidServiceDescriptionException
from scim2_client.errors import RequestNetworkException
from scim2_client.errors import ResponsePayloadValidationException
from scim2_client.errors import SCIMClientException
from scim2_client.errors import SCIMResponseException
from scim2_client.errors import UnexpectedContentFormatException
from scim2_client.errors import UnexpectedContentTypeException
from scim2_client.errors import UnexpectedStatusCodeException
from scim2_client.errors import request_validation_exception
from scim2_client.errors import server_error_exception

ResourceT = TypeVar("ResourceT", bound=Resource[Any])
MethodT = TypeVar("MethodT", bound=Callable[..., Any])
PublishedT = TypeVar("PublishedT")
ScimObjectT = TypeVar("ScimObjectT", bound=ScimObject)

NOT_MODIFIED = 304

BASE_HEADERS = {
    "Accept": "application/scim+json",
    "Content-Type": "application/scim+json",
}
CONFIG_RESOURCES = (ResourceType, Schema, ServiceProviderConfig)

# The sub-delims, ':' and '@' that RFC 3986 §3.3 allows in a path segment.
_PATH_SEGMENT_SAFE = "!$&'()*+,;=:@"

# Discovery cannot build the models from an Error object or a raw payload.
DISCOVERY_OPTIONS: dict[str, Any] = {
    "raise_scim_errors": True,
    "check_response_payload": True,
}


class ResponseHeaders(Protocol):
    """The headers of a response, looked up by case-insensitive names."""

    def get(self, key: str, /) -> str | None: ...


class RawResponse(Protocol):
    """A response as returned by the HTTP library of an engine."""

    @property
    def status_code(self) -> int:
        """The HTTP status code."""

    @property
    def headers(self) -> ResponseHeaders:
        """The HTTP headers."""

    @property
    def text(self) -> str:
        """The body, decoded as text."""


def describe_resource_models(
    resource_models: Collection[type[Resource[Any]]],
) -> tuple[tuple[DescribedModel, ...], tuple[ResourceType, ...]]:
    """Split composed models into the bare models and the resource types binding them.

    A :class:`~scim2_models.ScimProvider` lists the resources and the extensions
    apart, and binds them with a :class:`~scim2_models.ResourceType`, where the
    client is handed models such as ``User[EnterpriseUser]``.
    """
    models: dict[str, DescribedModel] = {}
    resource_types = []
    for resource_model in resource_models:
        # 'User[EnterpriseUser]' is a subclass scim2-models builds to carry the
        # extension fields, and the resource it describes is its base.
        extensions = getattr(resource_model, "__scim_extension_metadata__", ())
        described = (
            cast("DescribedModel", resource_model.__bases__[0])
            if extensions
            else resource_model
        )
        models[str(described.__schema__)] = described
        for extension in extensions:
            models[str(extension.__schema__)] = extension
        resource_types.append(ResourceType.from_resource(resource_model))

    return tuple(models.values()), tuple(resource_types)


def _under_provider(method: MethodT) -> MethodT:
    """Lend the description of the server to the payloads a method reads and writes.

    The policy the description carries then rules how much a payload may depart
    from the specification, down to the passes scim2-models makes on its own.
    """

    @wraps(method)
    def wrapper(self: "SCIMClient", /, *args: Any, **kwargs: Any) -> Any:
        with self.provider:
            return method(self, *args, **kwargs)

    return cast(MethodT, wrapper)


def _deprecation(message: str) -> None:
    """Emit a deprecation warning for the first caller outside of scim2-client."""
    package = os.path.dirname(__file__)
    frame = sys._getframe(0)
    level = 1
    while frame.f_back is not None and frame.f_code.co_filename.startswith(package):
        frame = frame.f_back
        level += 1

    warnings.warn(message, DeprecationWarning, stacklevel=level)


def _parametrize(
    generic: type[ScimObjectT], models: Sequence[type[Resource[Any]]]
) -> type[ScimObjectT]:
    """Parametrize a generic message with the union of models, known at runtime."""
    return cast("type[ScimObjectT]", cast(Any, generic)[Union[tuple(models)]])  # noqa: UP007


def _resource_url(endpoint: str, id: str) -> str:
    """Append an id to an endpoint as a single path segment.

    RFC 7643 §3.1 puts no constraint on the characters of an id, so the
    characters that would end the segment, such as '/', '?' or '#', are
    percent-encoded rather than refused. The dot segments are refused, as URL
    resolution would remove them instead of sending them to the server.
    """
    if id in (".", ".."):
        raise InvalidValueException(detail=f"'{id}' cannot be used as a resource id")

    return f"{endpoint}/{quote(id, safe=_PATH_SEGMENT_SAFE)}"


@dataclass
class RequestPayload:
    request_kwargs: dict[str, Any]
    url: str = ""
    payload: Any = None
    expected_types: list[type[ScimObject]] | None = None
    expected_status_codes: list[int] | None = None
    target: Resource[Any] | None = None


class SCIMClient:
    """The base model for request clients.

    It goal is to parse the requests and responses and check if they comply with the SCIM specifications.

    This class can be inherited and used as a basis for request engine integration.

    :param provider: The :class:`~scim2_models.ScimProvider` describing the server:
        the models it serves, the endpoints it serves them under, and the capabilities
        it declares. :meth:`~scim2_client.BaseSyncSCIMClient.discover` fills what it
        does not tell.
    :param resource_models: Deprecated, pass a :paramref:`provider` instead.
        A collection of :class:`~scim2_models.Resource` models expected to be handled by the SCIM client.
        If a request payload describe a resource that is not in this list, an exception will be raised.
    :param resource_types: Deprecated, pass a :paramref:`provider` instead.
        A collection of :class:`~scim2_models.ResourceType` that will be used to guess the
        server endpoints associated with the resources.
    :param service_provider_config: Deprecated, pass a :paramref:`provider` instead.
        An instance of :class:`~scim2_models.ServiceProviderConfig`.
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

    _provider: ScimProvider | None
    """The description of the server, rebuilt when one of its parts changes."""

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
    ``200`` is the only success code, as the individual operation results are
    carried by the response payload. ``413`` is answered when the request
    exceeds the limits the server advertises, as defined at
    :rfc:`RFC7644 §3.7.4 <7644#section-3.7.4>`. ``412`` is not expected, since
    a bulk request is never conditional as a whole.
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
        *,
        provider: ScimProvider | None = None,
        resource_models: Collection[type[Resource[Any]]] | None = None,
        resource_types: Collection[ResourceType] | None = None,
        service_provider_config: ServiceProviderConfig | None = None,
        check_request_payload: bool = True,
        check_response_payload: bool = True,
        check_response_content_type: bool = True,
        check_response_status_codes: bool = True,
        raise_scim_errors: bool = True,
    ):
        described = (resource_models, resource_types, service_provider_config)
        if any(parameter is not None for parameter in described):
            if provider is not None:
                raise TypeError(
                    "Cannot pass both 'provider' and 'resource_models', "
                    "'resource_types' or 'service_provider_config'"
                )

            warnings.warn(
                "The 'resource_models', 'resource_types' and "
                "'service_provider_config' parameters are deprecated, "
                "pass a 'provider' instead. "
                "Will be removed in 1.0.",
                DeprecationWarning,
                stacklevel=3,
            )

        derived_resource_types = provider is None and resource_types is None
        if provider is None:
            models, derived = describe_resource_models(resource_models or ())
            provider = ScimProvider(
                models=models,
                resource_types=derived if resource_types is None else resource_types,
                config=service_provider_config,
            )

        self.provider = provider
        self._derived_resource_types = derived_resource_types
        self.check_request_payload = check_request_payload
        self.check_response_payload = check_response_payload
        self.check_response_content_type = check_response_content_type
        self.check_response_status_codes = check_response_status_codes
        self.raise_scim_errors = raise_scim_errors

    @property
    def provider(self) -> ScimProvider:
        """The :class:`~scim2_models.ScimProvider` describing the server."""
        provider = self._provider
        if provider is None:
            provider = ScimProvider(
                models=self._models,
                resource_types=self._described_resource_types(),
                config=self._config,
                policy=self._policy,
            )
            self._provider = provider

        return provider

    @provider.setter
    def provider(self, provider: ScimProvider) -> None:
        self._models = provider.models
        self._resource_types = provider.resource_types
        self._config = provider.config
        self._policy = provider.policy
        self._derived_resource_types = False
        self._provider = provider

    def _described_resource_types(self) -> tuple[ResourceType, ...]:
        """Keep the resource types the known models describe.

        A description assembled attribute by attribute, as the deprecated
        attributes do, goes through states no provider could be built upon.
        """
        schemas = {str(model.__schema__).casefold() for model in self._models}
        return tuple(
            resource_type
            for resource_type in self._resource_types
            if str(resource_type.schema_).casefold() in schemas
        )

    @property
    def _composed_models(self) -> tuple[type[Resource[Any]], ...]:
        """The models the server endpoints serve, extensions included."""
        provider = self.provider
        return tuple(
            cast("type[Resource[Any]]", provider.model_for(resource_type))
            for resource_type in provider.resource_types
        )

    @staticmethod
    def _warn_description_deprecation(name: str) -> None:
        warnings.warn(
            f"'{name}' is deprecated, use 'provider' instead. Will be removed in 1.0.",
            DeprecationWarning,
            stacklevel=3,
        )

    @property
    def resource_models(self) -> tuple[type[Resource[Any]], ...]:
        """Deprecated, read :attr:`provider` instead."""
        self._warn_description_deprecation("resource_models")
        return self._composed_models

    @resource_models.setter
    def resource_models(self, resource_models: Collection[type[Resource[Any]]]) -> None:
        self._warn_description_deprecation("resource_models")
        models, derived = describe_resource_models(resource_models or ())
        self._models = models
        if self._derived_resource_types:
            self._resource_types = derived
        self._provider = None

    @property
    def resource_types(self) -> tuple[ResourceType, ...] | None:
        """Deprecated, read :attr:`provider` instead."""
        self._warn_description_deprecation("resource_types")
        return self._resource_types or None

    @resource_types.setter
    def resource_types(self, resource_types: Collection[ResourceType] | None) -> None:
        self._warn_description_deprecation("resource_types")
        self._derived_resource_types = resource_types is None
        self._resource_types = tuple(resource_types or ())
        self._provider = None

    @property
    def service_provider_config(self) -> ServiceProviderConfig | None:
        """Deprecated, read :attr:`provider` instead."""
        self._warn_description_deprecation("service_provider_config")
        return self._config

    @service_provider_config.setter
    def service_provider_config(
        self, service_provider_config: ServiceProviderConfig | None
    ) -> None:
        self._warn_description_deprecation("service_provider_config")
        self._config = service_provider_config
        self._provider = None

    def get_resource_model(self, name: str) -> type[Resource[Any]] | None:
        """Get a registered model by its name or its schema."""
        model = self.provider.model_for(name)
        if model is None or issubclass(model, Extension):
            return None

        composed_models = self._composed_models
        if model in composed_models:
            return model

        # 'model_for' answers the bare resource for a schema URI, where the client
        # hands out the model an endpoint serves, extensions included.
        for composed in composed_models:
            if composed.__schema__ == model.__schema__:
                return composed

        return cast("type[Resource[Any]]", model)

    def _check_resource_model(self, resource_model: type[Resource[Any]]) -> None:
        if self.provider.model_for(str(resource_model.__schema__)) is None:
            raise InvalidValueException(
                detail=f"Unknown resource type: '{resource_model}'"
            )

    @property
    def _etag_supported(self) -> bool:
        spc = self.provider.config
        return bool(spc and spc.etag and spc.etag.supported)

    @staticmethod
    def _resource_version(
        resource: Resource[Any] | dict[str, Any] | None,
    ) -> str | None:
        """Read the ETag a resource was read with."""
        if isinstance(resource, Resource):
            return resource.meta.version if resource.meta else None

        if isinstance(resource, dict):
            return (resource.get("meta") or {}).get("version")

        return None

    def _set_if_match(
        self, req: RequestPayload, resource: Resource[Any] | dict[str, Any] | None
    ) -> None:
        """Make a write request conditional on the resource not having changed."""
        version = self._resource_version(resource)
        if not version or not self._etag_supported:
            return

        headers = req.request_kwargs.setdefault("headers", {})
        headers.setdefault("If-Match", version)

    def _set_if_none_match(self, req: RequestPayload, resource: Resource[Any]) -> None:
        """Make a read request conditional on the resource having changed."""
        version = self._resource_version(resource)
        if not version or not self._etag_supported:
            return

        req.target = resource
        headers = req.request_kwargs.setdefault("headers", {})
        headers.setdefault("If-None-Match", version)

    @staticmethod
    def _set_version_from_etag(result: object, headers: ResponseHeaders) -> None:
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
    def _unchecked_url(req: RequestPayload) -> str:
        """Read the url of a request whose payload is sent without being read."""
        url = req.request_kwargs.pop("url", None)
        if url is None:
            raise InvalidValueException(
                detail="A url is required when the request payload is not checked"
            )

        return cast(str, url)

    @staticmethod
    def _renamed_target(target: Any, resource: Any) -> Any:
        """Read the target passed under the deprecated 'resource' name."""
        if resource is None:
            return target

        if target is not None:
            raise InvalidValueException(
                detail="Cannot pass both 'target' and 'resource'"
            )

        _deprecation(
            "The 'resource' parameter is renamed 'target'. Will be removed in 0.12."
        )
        return resource

    @staticmethod
    def _resolve_target(
        target: type[Resource[Any]] | Resource[Any] | ResourceType | str | None,
        id: str | Resource[Any] | None,
    ) -> tuple[
        type[Resource[Any]] | None,
        ResourceType | str | None,
        Resource[Any] | None,
        str | None,
    ]:
        """Read the model, the resource type, the resource object and the id a request is about.

        The target is a model, a resource type or its name, or a resource
        object standing for both the resource type and the id. The id is a
        string, or a resource object carrying it.
        """
        resource_type: ResourceType | str | None = None
        resource_model: type[Resource[Any]] | None = None
        if isinstance(target, ResourceType | str):
            resource_type = target

        elif isinstance(target, Resource):
            if id is not None:
                raise InvalidValueException(
                    detail="Cannot pass both a resource object and an id"
                )
            id = target

        else:
            resource_model = target

        if not isinstance(id, Resource):
            return resource_model, resource_type, None, id

        if resource_model is not None and not isinstance(id, resource_model):
            raise InvalidValueException(
                detail=f"Expected a {resource_model.__name__} resource, "
                f"got {type(id).__name__}"
            )

        if not id.id:
            raise InvalidValueException(detail="Resource must have an id")

        return type(id), resource_type, id, id.id

    @staticmethod
    def _resolve_payload_target(
        target: Any, resource: Any
    ) -> tuple[
        type[Resource[Any]] | ResourceType | str | None,
        Resource[Any] | dict[str, Any],
    ]:
        """Tell the target of a creation or a replacement from its payload."""
        if (
            resource is None
            and isinstance(target, Resource | dict)
            and not isinstance(target, ResourceType)
        ):
            return None, target

        if not isinstance(target, ResourceType | str | type | None):
            raise InvalidValueException(detail="Cannot pass two resources")

        if resource is None:
            raise InvalidValueException(detail="Missing resource")

        if not isinstance(resource, Resource | dict):
            raise InvalidValueException(
                detail="The resource must be a resource object or a payload"
            )

        return target, resource

    def _validate_payload_target(
        self,
        target: type[Resource[Any]] | ResourceType | str | None,
        resource: Resource[Any] | dict[str, Any],
        scim_ctx: Context,
    ) -> tuple[Resource[Any], ResourceType]:
        """Build the resource a creation or a replacement sends, and find its resource type."""
        resource_model = target if isinstance(target, type) else None
        resource_type = None if isinstance(target, type) else target
        if isinstance(resource, dict):
            if resource_model is None:
                guessed = get_model_by_payload(self._composed_models, resource)
                if guessed is None or not issubclass(guessed, Resource):
                    raise InvalidValueException(
                        detail="Cannot guess resource type from the payload"
                    )
                resource_model = guessed

            try:
                resource = resource_model.model_validate(resource)
            except ValidationError as exc:
                raise request_validation_exception(exc, scim_ctx) from exc

        elif resource_model is not None and not isinstance(resource, resource_model):
            raise InvalidValueException(
                detail=f"Expected a {resource_model.__name__} resource, "
                f"got {type(resource).__name__}"
            )

        resource_model = type(resource)
        self._check_resource_model(resource_model)
        found = self._resolve_resource_type(resource_model, resource, resource_type)
        return resource, found

    def resource_endpoint(
        self,
        target: type[Resource[Any]] | Resource[Any] | ResourceType | str | None,
    ) -> str:
        """Find the :attr:`~scim2_models.ResourceType.endpoint` a request is sent to.

        :param target: A :class:`~scim2_models.ResourceType`, or its name or id.
            A :class:`~scim2_models.Resource` model goes to the resource type
            named after its schema. A :class:`~scim2_models.Resource` object goes
            to the resource type of its ``meta.resourceType``.
        """
        resource_model, resource_type, resource, _ = self._resolve_target(target, None)
        return self._resolve_endpoint(resource_model, resource, resource_type)[0]

    def _resolve_endpoint(
        self,
        resource_model: type[Resource[Any]] | None,
        resource: Resource[Any] | None,
        resource_type: ResourceType | str | None,
    ) -> tuple[str, type[Resource[Any]] | None]:
        """Find the endpoint a request is sent to, and the model this endpoint serves."""
        if resource_type is None:
            if resource_model is None:
                return "/", None

            if resource_model in (ResourceType, Schema):
                return f"/{resource_model.__name__}s", resource_model

            # This one takes no final 's'
            if resource_model is ServiceProviderConfig:
                return "/ServiceProviderConfig", resource_model

        found = self._resolve_resource_type(resource_model, resource, resource_type)
        served = cast("type[Resource[Any]]", self.provider.model_for(found))
        return self._check_endpoint(found.endpoint), served

    def _find_resource_type(self, key: ResourceType | str) -> ResourceType | None:
        """Find a resource type of the provider by its name, or else by its id."""
        name = str(key.name if isinstance(key, ResourceType) else key).casefold()
        resource_types = self.provider.resource_types
        for attribute in ("name", "id"):
            for resource_type in resource_types:
                if str(getattr(resource_type, attribute)).casefold() == name:
                    return resource_type

        return None

    @staticmethod
    def _serves(
        resource_type: ResourceType, resource_model: type[Resource[Any]] | None
    ) -> bool:
        """Tell whether a resource type serves the schema and the extensions of a model."""
        if resource_model is None:
            return True

        if (
            str(resource_type.schema_).casefold()
            != str(resource_model.__schema__).casefold()
        ):
            return False

        declared = {
            str(extension.schema_).casefold()
            for extension in resource_type.schema_extensions or []
        }
        carried = {
            str(extension.__schema__).casefold()
            for extension in getattr(resource_model, "__scim_extension_metadata__", ())
        }
        return carried <= declared

    def _resolve_resource_type(
        self,
        resource_model: type[Resource[Any]] | None,
        resource: Resource[Any] | None,
        resource_type: ResourceType | str | None,
    ) -> ResourceType:
        """Find the resource type a request is about.

        The resource type is the one passed, or else the one in the
        ``meta.resourceType`` of the resource, or else the one named after the
        schema of the model.
        """
        declared = resource.meta.resource_type if resource and resource.meta else None
        if resource_type is not None:
            return self._explicit_resource_type(resource_model, declared, resource_type)

        if declared:
            found = self._find_resource_type(declared)
            if found and self._serves(found, resource_model):
                return found

            _deprecation(
                f"The resource type '{declared}' of the resource is unknown "
                f"or does not serve it. This will raise an error in 0.12."
            )

        model = cast("type[Resource[Any]]", resource_model)
        found = self._find_resource_type(str(model.__schema__).split(":")[-1])
        if found and self._serves(found, model):
            return found

        return self._guess_resource_type(model)

    def _explicit_resource_type(
        self,
        resource_model: type[Resource[Any]] | None,
        declared: str | None,
        resource_type: ResourceType | str,
    ) -> ResourceType:
        """Check that a resource type passed by the caller can serve the request."""
        found = self._find_resource_type(resource_type)
        if found is None:
            name = (
                resource_type.name
                if isinstance(resource_type, ResourceType)
                else resource_type
            )
            raise InvalidValueException(detail=f"Unknown resource type: '{name}'")

        if declared and self._find_resource_type(declared) is not found:
            raise InvalidValueException(
                detail=f"The resource belongs to the resource type '{declared}', "
                f"not '{found.name}'"
            )

        if not self._serves(found, resource_model):
            model_name = cast("type[Resource[Any]]", resource_model).__name__
            raise InvalidValueException(
                detail=f"The resource type '{found.name}' does not serve {model_name}"
            )

        return found

    def _guess_resource_type(self, resource_model: type[Resource[Any]]) -> ResourceType:
        """Find a resource type serving a model, the way versions before 0.11 did."""
        provider = self.provider
        schema = str(resource_model.__schema__)
        guessed = next(
            (
                resource_type
                for resource_type in provider.resource_types
                if provider.model_for(resource_type) is resource_model
            ),
            None,
        ) or next(
            (
                resource_type
                for resource_type in provider.resource_types
                if str(resource_type.schema_) == schema
            ),
            None,
        )
        if guessed is None:
            raise InvalidValueException(
                detail=f"No ResourceType is matching the schema: {schema}"
            )

        _deprecation(
            f"No resource type named after the schema '{schema}' serves "
            f"{resource_model.__name__}. Guessing the resource type is deprecated, "
            f"pass the resource type instead. Will be removed in 0.12."
        )
        return guessed

    @staticmethod
    def _check_required_extensions(
        resource_type: ResourceType, payload: dict[str, Any]
    ) -> None:
        """Refuse a payload missing an extension the resource type requires."""
        keys = {key.casefold() for key in payload}
        for extension in resource_type.schema_extensions or []:
            if extension.required and str(extension.schema_).casefold() not in keys:
                raise InvalidValueException(
                    detail=f"The resource type '{resource_type.name}' requires "
                    f"the extension '{extension.schema_}'"
                )

    def _check_endpoint(self, endpoint: str | None) -> str:
        """Refuse a resource type endpoint that would lead a request away from the server.

        The endpoints come from the description of the server, which could
        otherwise send the requests, and the credentials they carry, to another
        host or outside of the base URL. The resource id is appended to the
        endpoint, so a query or a fragment would swallow it.
        """
        if endpoint is None:
            raise InvalidServiceDescriptionException(
                message="A resource type has no endpoint"
            )

        if (
            "?" in endpoint
            or "#" in endpoint
            or not self._stays_under_base_url(endpoint)
        ):
            raise InvalidServiceDescriptionException(
                message=f"The endpoint '{endpoint}' is not under the base URL"
            )

        return endpoint

    def _stays_under_base_url(self, endpoint: str) -> bool:
        """Tell whether requests sent to an endpoint stay under the base URL.

        Without knowing the base URL, only the paths relative to it, without
        dot segments, are known to stay under it.
        """
        parts = urlsplit(endpoint)
        segments = set(parts.path.split("/"))
        return not (parts.scheme or parts.netloc or segments & {".", ".."})

    def register_naive_resource_types(self) -> None:
        """Register a *naive* :class:`~scim2_models.ResourceType` for each model the :attr:`provider` describes.

        This fills the :class:`~scim2_models.ResourceType` with generic values.
        The endpoint is the resource name with a *s* suffix.
        For instance, the :class:`~scim2_models.User` will have a `/Users` endpoint.

        .. deprecated:: 0.9

            A :class:`~scim2_models.ScimProvider` given no
            :class:`~scim2_models.ResourceType` builds those values itself.
            Will be removed in 1.0.
        """
        warnings.warn(
            "'register_naive_resource_types' is deprecated, a provider given no "
            "resource type builds naive ones itself. "
            "Will be removed in 1.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        self._resource_types = tuple(
            ResourceType.from_resource(model)
            for model in self._composed_models
            if model not in CONFIG_RESOURCES
        )
        self._derived_resource_types = True
        self._provider = None

    def _check_status_codes(
        self, status_code: int, expected_status_codes: list[int] | None
    ) -> None:
        if (
            self.check_response_status_codes
            and expected_status_codes
            and status_code not in expected_status_codes
        ):
            raise UnexpectedStatusCodeException(status_code)

    def _check_content_types(self, headers: ResponseHeaders) -> None:
        # Interoperability considerations:  The "application/scim+json" media
        # type is intended to identify JSON structure data that conforms to
        # the SCIM protocol and schema specifications.  Older versions of
        # SCIM are known to informally use "application/json".
        # https://datatracker.ietf.org/doc/html/rfc7644.html#section-8.1

        actual_content_type = (headers.get("content-type") or "").split(";").pop(0)
        expected_response_content_types = ("application/scim+json", "application/json")
        if (
            self.check_response_content_type
            and actual_content_type not in expected_response_content_types
        ):
            raise UnexpectedContentTypeException(content_type=actual_content_type)

    @_under_provider
    def check_response(
        self,
        payload: dict[str, Any] | None,
        status_code: int,
        headers: ResponseHeaders,
        expected_status_codes: list[int] | None = None,
        expected_types: Sequence[type[ScimObject]] | None = None,
        check_response_payload: bool | None = None,
        raise_scim_errors: bool | None = None,
        scim_ctx: Context | None = None,
        target: Resource[Any] | None = None,
    ) -> ScimObject | dict[str, Any] | None:
        """Build the object a server response describes, and check it on the way.

        This is what an engine calls once it has performed a request. The content type,
        the :class:`~scim2_models.Error` the server may have returned, the status code and
        the payload are examined in that order.

        :param payload: The decoded body of the response, or :data:`None` when it carried none.
        :param status_code: The HTTP status code of the response.
        :param headers: The headers of the response.
        :param expected_status_codes: The status codes the operation defines,
            :data:`None` for any.
        :param expected_types: The resource types the operation may return.
        :param check_response_payload: Overrides
            :paramref:`~scim2_client.SCIMClient.check_response_payload` for this response.
        :param raise_scim_errors: Overrides
            :paramref:`~scim2_client.SCIMClient.raise_scim_errors` for this response.
        :param scim_ctx: The :class:`~scim2_models.Context` the payload is validated under.
        :param target: The resource the request was made conditional upon, returned as it is
            when the server answers a ``304 Not Modified``.
        :raises ~scim2_client.SCIMResponseException: When the response cannot be read as the
            operation expects.
        """
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

        self._check_payload_shape(response_payload)

        if response_payload and response_payload.get("schemas") == [Error.__schema__]:
            try:
                error = Error.model_validate(response_payload)
            except ValidationError as exc:
                scim_exc = ResponsePayloadValidationException()
                scim_exc.add_note(str(exc))
                raise scim_exc from exc

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
            scim_exc.add_note(str(exc))
            raise scim_exc from exc

        self._set_version_from_etag(result, headers)
        return result

    def _query_kwargs(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Pass the query parameters to :meth:`request` as the HTTP library of the engine takes them."""
        return {"params": payload}

    def _request_kwargs(self, method: str, req: RequestPayload) -> dict[str, Any]:
        """Build the arguments a prepared request is sent with."""
        body: dict[str, Any] = {}
        if method == "GET" and req.payload:
            body = self._query_kwargs(req.payload)

        elif method not in ("GET", "DELETE"):
            body = {"json": req.payload}

        return {**body, **req.request_kwargs}

    def _parse_json(self, response: RawResponse) -> Any:
        """Parse the body of a response as the HTTP library of the engine does."""
        return json.loads(response.text)

    def _decode_payload(self, response: RawResponse) -> Any:
        """Decode the JSON body of a response, or return None when it has no body.

        A body too deeply nested for the decoder, or holding an integer too long for
        Python to convert, is reported as any other body that is not valid JSON.
        """
        try:
            return self._parse_json(response) if response.text else None
        except (ValueError, RecursionError) as exc:
            raise UnexpectedContentFormatException(source=response) from exc

    def _read_response(
        self,
        response: RawResponse,
        req: RequestPayload,
        check_response_payload: bool | None,
        raise_scim_errors: bool | None,
        scim_ctx: Context | None = None,
    ) -> ScimObject | dict[str, Any] | None:
        """Build the object the response to a prepared request describes."""
        try:
            return self.check_response(
                payload=self._decode_payload(response),
                status_code=response.status_code,
                headers=response.headers,
                expected_status_codes=req.expected_status_codes,
                expected_types=req.expected_types,
                check_response_payload=check_response_payload,
                raise_scim_errors=raise_scim_errors,
                scim_ctx=scim_ctx,
                target=req.target,
            )

        except (SCIMClientException, SCIMException) as exc:
            # SCIMException comes from scim2-models and has no 'source' attribute.
            exc.source = response  # type: ignore[union-attr]
            raise

    @staticmethod
    def _check_payload_shape(payload: object) -> None:
        """Refuse a payload that cannot be a SCIM message.

        A SCIM message is a JSON object, and its 'schemas', when present, is a list
        of URIs. The payload is read as such afterwards.
        """
        if payload is None:
            return

        if not isinstance(payload, dict):
            raise UnexpectedContentFormatException(
                message="The response payload is not a JSON object"
            )

        schemas = payload.get("schemas", [])
        if not isinstance(schemas, list) or not all(
            isinstance(schema, str) for schema in schemas
        ):
            raise UnexpectedContentFormatException(
                message="The schemas of the response payload are not a list of strings"
            )

    @staticmethod
    def _published(result: PublishedT | None) -> PublishedT:
        """Return what a discovery endpoint published, refusing an empty response."""
        if result is None:
            raise InvalidServiceDescriptionException(
                message="A discovery endpoint returned no content"
            )

        return result

    @_under_provider
    def _prepare_create_request(
        self,
        target: Any = None,
        resource: Resource[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        expected_status_codes: list[int] | None = None,
        **kwargs: Any,
    ) -> RequestPayload:
        target, resource = self._resolve_payload_target(target, resource)
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )
        if check_request_payload is None:
            check_request_payload = self.check_request_payload

        if not check_request_payload:
            req.payload = resource
            req.url = self._unchecked_url(req)
            return req

        resource, found = self._validate_payload_target(
            target, resource, Context.RESOURCE_CREATION_REQUEST
        )
        req.expected_types = [
            cast("type[Resource[Any]]", self.provider.model_for(found))
        ]
        req.payload = resource.model_dump(scim_ctx=Context.RESOURCE_CREATION_REQUEST)
        self._check_required_extensions(found, req.payload)
        req.url = req.request_kwargs.pop("url", self._check_endpoint(found.endpoint))
        return req

    @_under_provider
    def _prepare_query_request(
        self,
        target: type[Resource[Any]] | Resource[Any] | ResourceType | str | None = None,
        id: str
        | Resource[Any]
        | ResponseParameters[Any]
        | dict[str, Any]
        | None = None,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        expected_status_codes: list[int] | None = None,
        **kwargs: Any,
    ) -> RequestPayload:
        # The id is optional, so the query parameters may take its place.
        if not isinstance(id, str | Resource | None):
            if query_parameters is not None:
                raise InvalidValueException(detail="Cannot pass query parameters twice")
            id, query_parameters = None, id

        resource_model, resource_type, resource, id = self._resolve_target(target, id)
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )

        if check_request_payload is None:
            check_request_payload = self.check_request_payload

        if resource_model and check_request_payload:
            self._check_resource_model(resource_model)

        if check_request_payload and isinstance(query_parameters, dict):
            try:
                query_parameters = SearchRequest.model_validate(
                    query_parameters, scim_ctx=Context.RESOURCE_QUERY_REQUEST
                )
            except ValidationError as exc:
                raise request_validation_exception(
                    exc, Context.RESOURCE_QUERY_REQUEST
                ) from exc

        payload: Any
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
        endpoint, resource_model = self._resolve_endpoint(
            resource_model, resource, resource_type
        )
        req.url = req.request_kwargs.pop("url", endpoint)

        if resource_model is None:
            req.expected_types = [
                *self._composed_models,
                _parametrize(ListResponse, self._composed_models),
            ]

        elif resource_model == ServiceProviderConfig:
            req.expected_types = [resource_model]
            if id:
                raise InvalidValueException(
                    detail="ServiceProviderConfig cannot have an id"
                )

        elif id:
            req.expected_types = [resource_model]
            req.url = _resource_url(req.url, id)
            # A 304 answer has no payload, so the object can only be returned
            # back when it is the whole resource that was asked for.
            if resource is not None and not payload:
                self._set_if_none_match(req, resource)

        else:
            req.expected_types = [_parametrize(ListResponse, [resource_model])]

        return req

    @_under_provider
    def _prepare_search_request(
        self,
        target: Any = None,
        search_request: SearchRequest[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        expected_status_codes: list[int] | None = None,
        **kwargs: Any,
    ) -> RequestPayload:
        if search_request is None and isinstance(target, SearchRequest | dict):
            target, search_request = None, target

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
                cast("SearchRequest[Any]", search_request).model_dump(
                    exclude_unset=True, scim_ctx=Context.SEARCH_REQUEST
                )
                if search_request
                else None
            )

        if target is None:
            req.url = req.request_kwargs.pop("url", "/.search")
            req.expected_types = [_parametrize(ListResponse, self._composed_models)]
            return req

        resource_model, resource_type, resource, _ = self._resolve_target(target, None)
        endpoint, resource_model = self._resolve_endpoint(
            resource_model, resource, resource_type
        )
        req.url = req.request_kwargs.pop("url", f"{endpoint}/.search")
        req.expected_types = [
            _parametrize(ListResponse, [cast("type[Resource[Any]]", resource_model)])
        ]
        return req

    @property
    def _bulk_config(self) -> Bulk | None:
        """Read the bulk capabilities the server advertises, if they are known."""
        spc = self.provider.config
        return spc.bulk if spc else None

    def _check_bulk_support(self) -> None:
        """Refuse a bulk request the server advertised it does not serve."""
        bulk = self._bulk_config
        if bulk and bulk.supported is False:
            raise InvalidValueException(
                detail="The server does not support bulk requests"
            )

    def _check_bulk_limits(
        self, bulk_request: BulkRequest[Resource[Any]], payload: dict[str, Any]
    ) -> None:
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

    def _check_bulk_resource_models(
        self, bulk_request: BulkRequest[Resource[Any]]
    ) -> None:
        """Check that every operation carries a resource the client handles."""
        for operation in bulk_request.operations or []:
            if isinstance(operation.data, Resource):
                self._check_resource_model(operation.data.__class__)

    def _validate_bulk_request(
        self, bulk_request: BulkRequest[Resource[Any]] | dict[str, Any]
    ) -> BulkRequest[Resource[Any]]:
        """Build the bulk request message a raw payload describes."""
        if not isinstance(bulk_request, dict):
            return bulk_request

        try:
            return _parametrize(BulkRequest, self._composed_models).model_validate(
                bulk_request
            )
        except ValidationError as exc:
            raise request_validation_exception(exc, Context.BULK_REQUEST) from exc

    @_under_provider
    def _prepare_bulk_request(
        self,
        bulk_request: BulkRequest[Resource[Any]] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        expected_status_codes: list[int] | None = None,
        **kwargs: Any,
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
            message = self._validate_bulk_request(bulk_request)
            self._check_bulk_resource_models(message)
            payload = message.model_dump(scim_ctx=Context.BULK_REQUEST)
            self._check_bulk_limits(message, payload)
            req.payload = payload

        req.url = req.request_kwargs.pop("url", "/Bulk")
        req.expected_types = [_parametrize(BulkResponse, self._composed_models)]
        return req

    @_under_provider
    def _prepare_delete_request(
        self,
        target: Resource[Any] | type[Resource[Any]] | ResourceType | str | None = None,
        id: str | Resource[Any] | None = None,
        expected_status_codes: list[int] | None = None,
        *,
        resource: Resource[Any] | type[Resource[Any]] | None = None,
        **kwargs: Any,
    ) -> RequestPayload:
        target = self._renamed_target(target, resource)
        resource_model, resource_type, instance, id = self._resolve_target(target, id)
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )

        if resource_model is None and resource_type is None:
            raise InvalidValueException(detail="No resource type to delete")

        if resource_model is not None:
            self._check_resource_model(resource_model)

        if not id:
            raise InvalidValueException(detail="Resource must have an id")

        endpoint, _ = self._resolve_endpoint(resource_model, instance, resource_type)
        req.url = req.request_kwargs.pop("url", _resource_url(endpoint, id))
        self._set_if_match(req, instance)
        return req

    @_under_provider
    def _prepare_replace_request(
        self,
        target: Any = None,
        resource: Resource[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        expected_status_codes: list[int] | None = None,
        **kwargs: Any,
    ) -> RequestPayload:
        target, resource = self._resolve_payload_target(target, resource)
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )

        if check_request_payload is None:
            check_request_payload = self.check_request_payload

        if not check_request_payload:
            req.payload = resource
            req.url = self._unchecked_url(req)
            self._set_if_match(req, resource)
            return req

        resource, found = self._validate_payload_target(
            target, resource, Context.RESOURCE_REPLACEMENT_REQUEST
        )
        if not resource.id:
            raise InvalidValueException(detail="Resource must have an id")

        req.expected_types = [
            cast("type[Resource[Any]]", self.provider.model_for(found))
        ]
        req.payload = resource.model_dump(scim_ctx=Context.RESOURCE_REPLACEMENT_REQUEST)
        self._check_required_extensions(found, req.payload)
        req.url = req.request_kwargs.pop(
            "url", _resource_url(self._check_endpoint(found.endpoint), resource.id)
        )
        self._set_if_match(req, resource)
        return req

    @_under_provider
    def _prepare_patch_request(
        self,
        target: ResourceT | type[ResourceT] | ResourceType | str | None = None,
        id: str | ResourceT | PatchOp[ResourceT] | dict[str, Any] | None = None,
        patch_op: PatchOp[ResourceT] | dict[str, Any] | str | None = None,
        check_request_payload: bool | None = None,
        expected_status_codes: list[int] | None = None,
        *,
        resource: ResourceT | type[ResourceT] | None = None,
        **kwargs: Any,
    ) -> RequestPayload:
        """Prepare a PATCH request payload."""
        target = self._renamed_target(target, resource)
        # The id is optional, so the patch operation may take its place.
        if not isinstance(id, str | Resource | None):
            if isinstance(patch_op, str):
                _deprecation(
                    "Passing the patch operation before the id is deprecated, "
                    "pass the id first. Will be removed in 0.12."
                )
            elif patch_op is not None:
                raise InvalidValueException(
                    detail="Cannot pass the patch operation twice"
                )
            id, patch_op = patch_op, id

        resource_model, resource_type, instance, id = self._resolve_target(
            target, cast("str | Resource[Any] | None", id)
        )
        req = RequestPayload(
            expected_status_codes=expected_status_codes,
            request_kwargs=kwargs,
        )

        if check_request_payload is None:
            check_request_payload = self.check_request_payload

        if resource_model is None and resource_type is None:
            raise InvalidValueException(detail="No resource type to modify")

        if resource_model is not None:
            self._check_resource_model(resource_model)

        if not id:
            raise InvalidValueException(detail="Resource must have an id")

        if patch_op is None:
            raise InvalidValueException(detail="Missing patch operation")

        endpoint, served = self._resolve_endpoint(
            resource_model, instance, resource_type
        )
        req.url = req.request_kwargs.pop("url", _resource_url(endpoint, id))
        if not check_request_payload or isinstance(patch_op, dict):
            req.payload = patch_op

        else:
            try:
                req.payload = cast("PatchOp[Any]", patch_op).model_dump(
                    scim_ctx=Context.RESOURCE_PATCH_REQUEST
                )
            except ValidationError as exc:
                raise request_validation_exception(
                    exc, Context.RESOURCE_PATCH_REQUEST
                ) from exc

        req.expected_types = [cast("type[Resource[Any]]", served)]
        self._set_if_match(req, instance)
        return req

    def build_resource_models(
        self, resource_types: Collection[ResourceType], schemas: Collection[Schema]
    ) -> tuple[type[Resource[Any]], ...]:
        """Build models from server objects.

        .. deprecated:: 0.9

            Use :meth:`ScimProvider.from_discovery
            <scim2_models.ScimProvider.from_discovery>` instead.
            Will be removed in 1.0.
        """
        warnings.warn(
            "'build_resource_models' is deprecated, "
            "use 'ScimProvider.from_discovery' instead. "
            "Will be removed in 1.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        provider = ScimProvider.from_discovery(schemas, resource_types)
        return tuple(
            cast("type[Resource[Any]]", provider.model_for(resource_type))
            for resource_type in provider.resource_types
        )

    def _describe_service(
        self,
        schemas: Collection[Schema] | None,
        resource_types: Collection[ResourceType],
        config: ServiceProviderConfig | None,
    ) -> ScimProvider:
        """Build the description of the server, and tell its faults from ours."""
        try:
            if schemas is not None:
                return ScimProvider.from_discovery(
                    schemas, resource_types, config, self._policy
                )

            return ScimProvider(
                models=self._models,
                resource_types=resource_types,
                config=config,
                policy=self._policy,
            )

        except ScimProviderError as exc:
            raise InvalidServiceDescriptionException(message=str(exc)) from exc


class BaseSyncSCIMClient(SCIMClient):
    """Base class for synchronous request clients."""

    def _send(self, method: str, req: RequestPayload) -> RawResponse:
        try:
            return self.request(method, req.url, **self._request_kwargs(method, req))
        except RequestNetworkException as exc:
            exc.source = req.payload
            raise

    @overload
    def create(
        self,
        target: ResourceT,
        resource: None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    def create(
        self,
        target: type[ResourceT],
        resource: ResourceT | dict[str, Any],
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    def create(
        self,
        target: ResourceType | str | None,
        resource: ResourceT,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    def create(
        self,
        *,
        resource: ResourceT,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    def create(
        self,
        target: dict[str, Any] | ResourceType | str | None = None,
        resource: dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> Resource[Any] | Error | dict[str, Any]: ...

    def create(
        self,
        target: AnyResource
        | dict[str, Any]
        | type[Resource[Any]]
        | ResourceType
        | str
        | None = None,
        resource: AnyResource | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.CREATION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> AnyResource | Error | dict[str, Any]:
        """Perform a POST request to create, as defined in :rfc:`RFC7644 §3.3 <7644#section-3.3>`.

        :param target: The :class:`~scim2_models.ResourceType` to create the resource in, or its name or id, or a
            :class:`~scim2_models.Resource` model. When omitted, it is the one named after the schema of the resource.
            The resource itself may be passed here instead of :paramref:`resource`.
        :param resource: The resource to create.
            If it is a :class:`dict`, it is read with the model passed as :paramref:`target`,
            or else with the model guessed from its schemas.
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
        req = self._prepare_create_request(
            target=target,
            resource=resource,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = self._send("POST", req)
        return cast(
            "AnyResource | Error | dict[str, Any]",
            self._read_response(
                response,
                req,
                check_response_payload,
                raise_scim_errors,
                Context.RESOURCE_CREATION_RESPONSE,
            ),
        )

    @overload
    def query(
        self,
        target: type[ServiceProviderConfig],
        id: ResponseParameters[Any] | dict[str, Any] | None = None,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ServiceProviderConfig | Error | dict[str, Any]: ...

    @overload
    def query(
        self,
        target: ResourceType | str,
        id: str | Resource[Any],
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> Resource[Any] | Error | dict[str, Any]: ...

    @overload
    def query(
        self,
        target: ResourceType | str | None = None,
        id: ResponseParameters[Any] | dict[str, Any] | None = None,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ListResponse[Resource[Any]] | Error | dict[str, Any]: ...

    @overload
    def query(
        self,
        target: type[ResourceT],
        id: str | ResourceT,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    def query(
        self,
        target: ResourceT,
        id: ResponseParameters[Any] | dict[str, Any] | None = None,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    def query(
        self,
        target: type[ResourceT],
        id: ResponseParameters[Any] | dict[str, Any] | None = None,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ListResponse[ResourceT] | Error | dict[str, Any]: ...

    def query(
        self,
        target: type[Resource[Any]] | Resource[Any] | ResourceType | str | None = None,
        id: str
        | Resource[Any]
        | ResponseParameters[Any]
        | dict[str, Any]
        | None = None,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.QUERY_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> "Resource[Any] | ListResponse[Any] | Error | dict[str, Any]":
        """Perform a GET request to read resources, as defined in :rfc:`RFC7644 §3.4.2 <7644#section-3.4.2>`.

        The resource type is designated by :paramref:`target`.

        - If :paramref:`id` is not :data:`None`, the resource with this id is read.
        - If :paramref:`id` is :data:`None`, all the resources of the resource type are listed.
        - If :paramref:`target` is :data:`None`, all the available resources are listed.

        When the server supports ETags and a :class:`~scim2_models.Resource` object carrying
        a version is passed, the read is conditional, and the object itself is returned when
        the server answers with a ``304 Not Modified``.

        :param target: A :class:`~scim2_models.ResourceType`, or its name or id, or a
            :class:`~scim2_models.Resource` model, which goes to the resource type named after
            its schema. A :class:`~scim2_models.Resource` object stands for both the resource
            type, read from its ``meta.resourceType``, and the id.
        :param id: The id of the resource to read, or a :class:`~scim2_models.Resource` object
            carrying it. When :paramref:`target` is a :class:`~scim2_models.Resource` object,
            the query parameters may be passed here.
        :param query_parameters: A :class:`~scim2_models.ResponseParameters` or
            :class:`~scim2_models.SearchRequest` detailing the query parameters.
            Use :class:`~scim2_models.ResponseParameters` when querying a single
            resource by id, where only ``attributes`` and ``excludedAttributes``
            are meaningful (:rfc:`RFC 7644 §3.4.1 <7644#section-3.4.1>`).
            Use :class:`~scim2_models.SearchRequest` when listing resources, to
            also pass ``filter``, ``sortBy``, ``sortOrder``, ``startIndex`` and
            ``count`` (:rfc:`RFC 7644 §3.4.2 <7644#section-3.4.2>`).
            Pass ``cursor`` instead of ``startIndex`` for cursor-based pagination
            (:rfc:`RFC 9865 §2 <9865#section-2>`). An empty cursor requests the
            first page. The response gives the cursor of the next page in
            :attr:`~scim2_models.ListResponse.next_cursor`.
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
            response = scim.query("Employee", "my-user-id")
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
        req = self._prepare_query_request(
            target=target,
            id=id,
            query_parameters=query_parameters,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = self._send("GET", req)
        return cast(
            "Resource[Any] | ListResponse[Any] | Error | dict[str, Any]",
            self._read_response(
                response,
                req,
                check_response_payload,
                raise_scim_errors,
                Context.RESOURCE_QUERY_RESPONSE,
            ),
        )

    @overload
    def search(
        self,
        target: type[ResourceT],
        search_request: SearchRequest[Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ListResponse[ResourceT] | Error | dict[str, Any]: ...

    @overload
    def search(
        self,
        target: SearchRequest[Any] | ResourceType | str | None = None,
        search_request: SearchRequest[Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ListResponse[Resource[Any]] | Error | dict[str, Any]: ...

    def search(
        self,
        target: SearchRequest[Any]
        | type[Resource[Any]]
        | ResourceType
        | str
        | None = None,
        search_request: SearchRequest[Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.SEARCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> "ListResponse[Any] | Error | dict[str, Any]":
        """Perform a POST search request to read all available resources, as defined in :rfc:`RFC7644 §3.4.3 <7644#section-3.4.3>`.

        :param target: The :class:`~scim2_models.ResourceType` to search, or its name or id, or a
            :class:`~scim2_models.Resource` model. When omitted, the search covers all the
            resource types. The search request may be passed here instead of
            :paramref:`search_request`.
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
        req = self._prepare_search_request(
            target=target,
            search_request=search_request,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = self._send("POST", req)
        return cast(
            "ListResponse[Any] | Error | dict[str, Any]",
            self._read_response(
                response,
                req,
                check_response_payload,
                raise_scim_errors,
                Context.RESOURCE_QUERY_RESPONSE,
            ),
        )

    def bulk(
        self,
        bulk_request: BulkRequest[Resource[Any]] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = SCIMClient.BULK_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> BulkResponse[Resource[Any]] | Error | dict[str, Any]:
        """Perform a POST bulk request to execute bulk operations, as defined in :rfc:`RFC7644 §3.7 <7644#section-3.7>`.

        :param bulk_request: An object detailing the bulk request.
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
            When it is :data:`False`, :paramref:`bulk_request` is expected to be a dict
            that will be passed as-is in the request.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.

        :return:
            - A :class:`~scim2_models.Error` object in case of error.
            - A :class:`~scim2_models.BulkResponse` object in case of success.

        .. important::

            A bulk job the server processed answers ``200``, whatever the outcome of the
            operations it carried, as defined at :rfc:`RFC7644 §3.7.3 <7644#section-3.7.3>`.
            :paramref:`raise_scim_errors` is about the bulk job itself, so failed operations
            raise nothing: their ``status`` and the :class:`~scim2_models.Error` object
            their ``response`` carries are to be read one by one.

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
            for operation in response.operations:
                if operation.status >= 400:
                    print(operation.bulk_id, operation.response.detail)

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
        req = self._prepare_bulk_request(
            bulk_request=bulk_request,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = self._send("POST", req)
        return cast(
            "BulkResponse[Resource[Any]] | Error | dict[str, Any]",
            self._read_response(
                response,
                req,
                check_response_payload,
                raise_scim_errors,
                Context.BULK_RESPONSE,
            ),
        )

    def delete(
        self,
        target: Resource[Any] | type[Resource[Any]] | ResourceType | str | None = None,
        id: str | Resource[Any] | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.DELETION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        *,
        resource: Resource[Any] | type[Resource[Any]] | None = None,
        **kwargs: Any,
    ) -> Error | dict[str, Any] | None:
        """Perform a DELETE request, as defined in :rfc:`RFC7644 §3.6 <7644#section-3.6>`.

        The resource to delete is designated by a resource type and an id, or by a
        :class:`~scim2_models.Resource` object.

        :param target: A :class:`~scim2_models.ResourceType`, or its name or id, or a
            :class:`~scim2_models.Resource` model, which goes to the resource type named after
            its schema. A :class:`~scim2_models.Resource` object stands for both the resource
            type, read from its ``meta.resourceType``, and the id.
        :param id: The id of the resource to delete, or a :class:`~scim2_models.Resource`
            object carrying it.
        :param resource: Deprecated, pass :paramref:`target` instead.
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
        req = self._prepare_delete_request(
            target=target,
            resource=resource,
            id=id,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = self._send("DELETE", req)
        return cast(
            "Error | dict[str, Any] | None",
            self._read_response(
                response, req, check_response_payload, raise_scim_errors
            ),
        )

    @overload
    def replace(
        self,
        target: ResourceT,
        resource: None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    def replace(
        self,
        target: type[ResourceT],
        resource: ResourceT | dict[str, Any],
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    def replace(
        self,
        target: ResourceType | str | None,
        resource: ResourceT,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    def replace(
        self,
        *,
        resource: ResourceT,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    def replace(
        self,
        target: dict[str, Any] | ResourceType | str | None = None,
        resource: dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> Resource[Any] | Error | dict[str, Any]: ...

    def replace(
        self,
        target: AnyResource
        | dict[str, Any]
        | type[Resource[Any]]
        | ResourceType
        | str
        | None = None,
        resource: AnyResource | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.REPLACEMENT_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> AnyResource | Error | dict[str, Any]:
        """Perform a PUT request to replace a resource, as defined in :rfc:`RFC7644 §3.5.1 <7644#section-3.5.1>`.

        :param target: The :class:`~scim2_models.ResourceType` of the resource, or its name or id, or a
            :class:`~scim2_models.Resource` model. When omitted, it is the one in the ``meta.resourceType`` of
            the resource, or else the one named after its schema.
            The resource itself may be passed here instead of :paramref:`resource`.
        :param resource: The new resource. It must have an id.
            If it is a :class:`dict`, it is read with the model passed as :paramref:`target`,
            or else with the model guessed from its schemas.
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
        req = self._prepare_replace_request(
            target=target,
            resource=resource,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = self._send("PUT", req)
        return cast(
            "AnyResource | Error | dict[str, Any]",
            self._read_response(
                response,
                req,
                check_response_payload,
                raise_scim_errors,
                Context.RESOURCE_REPLACEMENT_RESPONSE,
            ),
        )

    def modify(
        self,
        target: ResourceT | type[ResourceT] | ResourceType | str | None = None,
        id: str | ResourceT | PatchOp[ResourceT] | dict[str, Any] | None = None,
        patch_op: PatchOp[ResourceT] | dict[str, Any] | str | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.PATCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        *,
        resource: ResourceT | type[ResourceT] | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any] | None:
        """Perform a PATCH request to modify a resource, as defined in :rfc:`RFC7644 §3.5.2 <7644#section-3.5.2>`.

        The resource to modify is designated by a resource type and an id, or by a
        :class:`~scim2_models.Resource` object.

        :param target: A :class:`~scim2_models.ResourceType`, or its name or id, or a
            :class:`~scim2_models.Resource` model, which goes to the resource type named after
            its schema. A :class:`~scim2_models.Resource` object stands for both the resource
            type, read from its ``meta.resourceType``, and the id.
        :param id: The id of the resource to modify, or a :class:`~scim2_models.Resource`
            object carrying it. When :paramref:`target` is a :class:`~scim2_models.Resource`
            object, the patch operation may be passed here.
        :param patch_op: The :class:`~scim2_models.PatchOp` object describing the modifications.
            Must be parameterized with the model of the resource
            (e.g., :code:`PatchOp[User]` for a :code:`User`).
        :param resource: Deprecated, pass :paramref:`target` instead.
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
        req = self._prepare_patch_request(
            target=target,
            resource=resource,
            patch_op=patch_op,
            id=id,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = self._send("PATCH", req)
        return cast(
            "ResourceT | Error | dict[str, Any] | None",
            self._read_response(
                response,
                req,
                check_response_payload,
                raise_scim_errors,
                Context.RESOURCE_PATCH_RESPONSE,
            ),
        )

    def discover(
        self,
        schemas: bool = True,
        resource_types: bool = True,
        service_provider_config: bool = True,
    ) -> None:
        """Dynamically discover the server configuration objects.

        Only what the :attr:`~scim2_client.SCIMClient.provider` does not describe
        yet is queried, so what the client was given takes precedence over what the
        server publishes.

        :param schemas: Whether to discover the :class:`~scim2_models.Schema` endpoint.
        :param resource_types: Whether to discover the :class:`~scim2_models.ResourceType` endpoint.
        :param service_provider_config: Whether to discover the :class:`~scim2_models.ServiceProviderConfig` endpoint.
        :raises ~scim2_client.InvalidServiceDescriptionException: When the objects
            the server publishes do not describe a coherent service.
        """
        discovered_resource_types: Collection[ResourceType] = self._resource_types
        if resource_types and not discovered_resource_types:
            resource_types_response = self.query(ResourceType, **DISCOVERY_OPTIONS)
            discovered_resource_types = (
                self._published(
                    cast("ListResponse[ResourceType] | None", resource_types_response)
                ).resources
                or []
            )

        discovered_schemas = None
        if schemas and not self._models:
            schemas_response = self.query(Schema, **DISCOVERY_OPTIONS)
            discovered_schemas = (
                self._published(
                    cast("ListResponse[Schema] | None", schemas_response)
                ).resources
                or []
            )

        config = self._config
        if service_provider_config and not config:
            config_response = self.query(ServiceProviderConfig, **DISCOVERY_OPTIONS)
            config = self._published(
                cast("ServiceProviderConfig | None", config_response)
            )

        self.provider = self._describe_service(
            discovered_schemas, discovered_resource_types, config
        )

    def request(self, method: str, url: str, **kwargs: Any) -> RawResponse:
        """Send a request to the server, without any SCIM processing.

        Neither the request nor the response is checked, so this is fitted to
        observe how the server behaves, for instance with an unsupported HTTP method.

        :param method: The HTTP method.
        :param url: The URL, relative to the SCIM server base URL.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.
        :return: The response of the underlying HTTP request library.
        :raises ~scim2_client.RequestNetworkException: When the request cannot be sent.

        :usage:

        .. code-block:: python
            :caption: Checking that the ``/Schemas`` endpoint refuses ``DELETE``

            response = scim.request("DELETE", "/Schemas")
            assert response.status_code == 405
        """
        raise NotImplementedError()


class BaseAsyncSCIMClient(SCIMClient):
    """Base class for asynchronous request clients."""

    async def _send(self, method: str, req: RequestPayload) -> RawResponse:
        try:
            return await self.request(
                method, req.url, **self._request_kwargs(method, req)
            )
        except RequestNetworkException as exc:
            exc.source = req.payload
            raise

    @overload
    async def create(
        self,
        target: ResourceT,
        resource: None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    async def create(
        self,
        target: type[ResourceT],
        resource: ResourceT | dict[str, Any],
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    async def create(
        self,
        target: ResourceType | str | None,
        resource: ResourceT,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    async def create(
        self,
        *,
        resource: ResourceT,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    async def create(
        self,
        target: dict[str, Any] | ResourceType | str | None = None,
        resource: dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> Resource[Any] | Error | dict[str, Any]: ...

    async def create(
        self,
        target: AnyResource
        | dict[str, Any]
        | type[Resource[Any]]
        | ResourceType
        | str
        | None = None,
        resource: AnyResource | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.CREATION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> AnyResource | Error | dict[str, Any]:
        """Perform a POST request to create, as defined in :rfc:`RFC7644 §3.3 <7644#section-3.3>`.

        :param target: The :class:`~scim2_models.ResourceType` to create the resource in, or its name or id, or a
            :class:`~scim2_models.Resource` model. When omitted, it is the one named after the schema of the resource.
            The resource itself may be passed here instead of :paramref:`resource`.
        :param resource: The resource to create.
            If it is a :class:`dict`, it is read with the model passed as :paramref:`target`,
            or else with the model guessed from its schemas.
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
        req = self._prepare_create_request(
            target=target,
            resource=resource,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = await self._send("POST", req)
        return cast(
            "AnyResource | Error | dict[str, Any]",
            self._read_response(
                response,
                req,
                check_response_payload,
                raise_scim_errors,
                Context.RESOURCE_CREATION_RESPONSE,
            ),
        )

    @overload
    async def query(
        self,
        target: type[ServiceProviderConfig],
        id: ResponseParameters[Any] | dict[str, Any] | None = None,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ServiceProviderConfig | Error | dict[str, Any]: ...

    @overload
    async def query(
        self,
        target: ResourceType | str,
        id: str | Resource[Any],
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> Resource[Any] | Error | dict[str, Any]: ...

    @overload
    async def query(
        self,
        target: ResourceType | str | None = None,
        id: ResponseParameters[Any] | dict[str, Any] | None = None,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ListResponse[Resource[Any]] | Error | dict[str, Any]: ...

    @overload
    async def query(
        self,
        target: type[ResourceT],
        id: str | ResourceT,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    async def query(
        self,
        target: ResourceT,
        id: ResponseParameters[Any] | dict[str, Any] | None = None,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    async def query(
        self,
        target: type[ResourceT],
        id: ResponseParameters[Any] | dict[str, Any] | None = None,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ListResponse[ResourceT] | Error | dict[str, Any]: ...

    async def query(
        self,
        target: type[Resource[Any]] | Resource[Any] | ResourceType | str | None = None,
        id: str
        | Resource[Any]
        | ResponseParameters[Any]
        | dict[str, Any]
        | None = None,
        query_parameters: ResponseParameters[Any] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.QUERY_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> "Resource[Any] | ListResponse[Any] | Error | dict[str, Any]":
        """Perform a GET request to read resources, as defined in :rfc:`RFC7644 §3.4.2 <7644#section-3.4.2>`.

        The resource type is designated by :paramref:`target`.

        - If :paramref:`id` is not :data:`None`, the resource with this id is read.
        - If :paramref:`id` is :data:`None`, all the resources of the resource type are listed.
        - If :paramref:`target` is :data:`None`, all the available resources are listed.

        When the server supports ETags and a :class:`~scim2_models.Resource` object carrying
        a version is passed, the read is conditional, and the object itself is returned when
        the server answers with a ``304 Not Modified``.

        :param target: A :class:`~scim2_models.ResourceType`, or its name or id, or a
            :class:`~scim2_models.Resource` model, which goes to the resource type named after
            its schema. A :class:`~scim2_models.Resource` object stands for both the resource
            type, read from its ``meta.resourceType``, and the id.
        :param id: The id of the resource to read, or a :class:`~scim2_models.Resource` object
            carrying it. When :paramref:`target` is a :class:`~scim2_models.Resource` object,
            the query parameters may be passed here.
        :param query_parameters: A :class:`~scim2_models.ResponseParameters` or
            :class:`~scim2_models.SearchRequest` detailing the query parameters.
            Use :class:`~scim2_models.ResponseParameters` when querying a single
            resource by id, where only ``attributes`` and ``excludedAttributes``
            are meaningful (:rfc:`RFC 7644 §3.4.1 <7644#section-3.4.1>`).
            Use :class:`~scim2_models.SearchRequest` when listing resources, to
            also pass ``filter``, ``sortBy``, ``sortOrder``, ``startIndex`` and
            ``count`` (:rfc:`RFC 7644 §3.4.2 <7644#section-3.4.2>`).
            Pass ``cursor`` instead of ``startIndex`` for cursor-based pagination
            (:rfc:`RFC 9865 §2 <9865#section-2>`). An empty cursor requests the
            first page. The response gives the cursor of the next page in
            :attr:`~scim2_models.ListResponse.next_cursor`.
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
            response = scim.query("Employee", "my-user-id")
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
        req = self._prepare_query_request(
            target=target,
            id=id,
            query_parameters=query_parameters,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = await self._send("GET", req)
        return cast(
            "Resource[Any] | ListResponse[Any] | Error | dict[str, Any]",
            self._read_response(
                response,
                req,
                check_response_payload,
                raise_scim_errors,
                Context.RESOURCE_QUERY_RESPONSE,
            ),
        )

    @overload
    async def search(
        self,
        target: type[ResourceT],
        search_request: SearchRequest[Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ListResponse[ResourceT] | Error | dict[str, Any]: ...

    @overload
    async def search(
        self,
        target: SearchRequest[Any] | ResourceType | str | None = None,
        search_request: SearchRequest[Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ListResponse[Resource[Any]] | Error | dict[str, Any]: ...

    async def search(
        self,
        target: SearchRequest[Any]
        | type[Resource[Any]]
        | ResourceType
        | str
        | None = None,
        search_request: SearchRequest[Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.SEARCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> "ListResponse[Any] | Error | dict[str, Any]":
        """Perform a POST search request to read all available resources, as defined in :rfc:`RFC7644 §3.4.3 <7644#section-3.4.3>`.

        :param target: The :class:`~scim2_models.ResourceType` to search, or its name or id, or a
            :class:`~scim2_models.Resource` model. When omitted, the search covers all the
            resource types. The search request may be passed here instead of
            :paramref:`search_request`.
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
        req = self._prepare_search_request(
            target=target,
            search_request=search_request,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = await self._send("POST", req)
        return cast(
            "ListResponse[Any] | Error | dict[str, Any]",
            self._read_response(
                response,
                req,
                check_response_payload,
                raise_scim_errors,
                Context.RESOURCE_QUERY_RESPONSE,
            ),
        )

    async def bulk(
        self,
        bulk_request: BulkRequest[Resource[Any]] | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = SCIMClient.BULK_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> BulkResponse[Resource[Any]] | Error | dict[str, Any]:
        """Perform a POST bulk request to execute bulk operations, as defined in :rfc:`RFC7644 §3.7 <7644#section-3.7>`.

        :param bulk_request: An object detailing the bulk request.
        :param check_request_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_request_payload`.
            When it is :data:`False`, :paramref:`bulk_request` is expected to be a dict
            that will be passed as-is in the request.
        :param check_response_payload: If set, overwrites :paramref:`scim2_client.SCIMClient.check_response_payload`.
        :param expected_status_codes: The list of expected status codes form the response.
            If :data:`None` any status code is accepted.
        :param raise_scim_errors: If set, overwrites :paramref:`scim2_client.SCIMClient.raise_scim_errors`.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.

        :return:
            - A :class:`~scim2_models.Error` object in case of error.
            - A :class:`~scim2_models.BulkResponse` object in case of success.

        .. important::

            A bulk job the server processed answers ``200``, whatever the outcome of the
            operations it carried, as defined at :rfc:`RFC7644 §3.7.3 <7644#section-3.7.3>`.
            :paramref:`raise_scim_errors` is about the bulk job itself, so failed operations
            raise nothing: their ``status`` and the :class:`~scim2_models.Error` object
            their ``response`` carries are to be read one by one.

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
            response = await scim.bulk(req)
            # 'response' may be a BulkResponse or an Error object
            for operation in response.operations:
                if operation.status >= 400:
                    print(operation.bulk_id, operation.response.detail)

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
        req = self._prepare_bulk_request(
            bulk_request=bulk_request,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = await self._send("POST", req)
        return cast(
            "BulkResponse[Resource[Any]] | Error | dict[str, Any]",
            self._read_response(
                response,
                req,
                check_response_payload,
                raise_scim_errors,
                Context.BULK_RESPONSE,
            ),
        )

    async def delete(
        self,
        target: Resource[Any] | type[Resource[Any]] | ResourceType | str | None = None,
        id: str | Resource[Any] | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.DELETION_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        *,
        resource: Resource[Any] | type[Resource[Any]] | None = None,
        **kwargs: Any,
    ) -> Error | dict[str, Any] | None:
        """Perform a DELETE request, as defined in :rfc:`RFC7644 §3.6 <7644#section-3.6>`.

        The resource to delete is designated by a resource type and an id, or by a
        :class:`~scim2_models.Resource` object.

        :param target: A :class:`~scim2_models.ResourceType`, or its name or id, or a
            :class:`~scim2_models.Resource` model, which goes to the resource type named after
            its schema. A :class:`~scim2_models.Resource` object stands for both the resource
            type, read from its ``meta.resourceType``, and the id.
        :param id: The id of the resource to delete, or a :class:`~scim2_models.Resource`
            object carrying it.
        :param resource: Deprecated, pass :paramref:`target` instead.
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
        req = self._prepare_delete_request(
            target=target,
            resource=resource,
            id=id,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = await self._send("DELETE", req)
        return cast(
            "Error | dict[str, Any] | None",
            self._read_response(
                response, req, check_response_payload, raise_scim_errors
            ),
        )

    @overload
    async def replace(
        self,
        target: ResourceT,
        resource: None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    async def replace(
        self,
        target: type[ResourceT],
        resource: ResourceT | dict[str, Any],
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    async def replace(
        self,
        target: ResourceType | str | None,
        resource: ResourceT,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    async def replace(
        self,
        *,
        resource: ResourceT,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any]: ...

    @overload
    async def replace(
        self,
        target: dict[str, Any] | ResourceType | str | None = None,
        resource: dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int] | None = ...,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> Resource[Any] | Error | dict[str, Any]: ...

    async def replace(
        self,
        target: AnyResource
        | dict[str, Any]
        | type[Resource[Any]]
        | ResourceType
        | str
        | None = None,
        resource: AnyResource | dict[str, Any] | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.REPLACEMENT_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        **kwargs: Any,
    ) -> AnyResource | Error | dict[str, Any]:
        """Perform a PUT request to replace a resource, as defined in :rfc:`RFC7644 §3.5.1 <7644#section-3.5.1>`.

        :param target: The :class:`~scim2_models.ResourceType` of the resource, or its name or id, or a
            :class:`~scim2_models.Resource` model. When omitted, it is the one in the ``meta.resourceType`` of
            the resource, or else the one named after its schema.
            The resource itself may be passed here instead of :paramref:`resource`.
        :param resource: The new resource. It must have an id.
            If it is a :class:`dict`, it is read with the model passed as :paramref:`target`,
            or else with the model guessed from its schemas.
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
        req = self._prepare_replace_request(
            target=target,
            resource=resource,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = await self._send("PUT", req)
        return cast(
            "AnyResource | Error | dict[str, Any]",
            self._read_response(
                response,
                req,
                check_response_payload,
                raise_scim_errors,
                Context.RESOURCE_REPLACEMENT_RESPONSE,
            ),
        )

    async def modify(
        self,
        target: ResourceT | type[ResourceT] | ResourceType | str | None = None,
        id: str | ResourceT | PatchOp[ResourceT] | dict[str, Any] | None = None,
        patch_op: PatchOp[ResourceT] | dict[str, Any] | str | None = None,
        check_request_payload: bool | None = None,
        check_response_payload: bool | None = None,
        expected_status_codes: list[int]
        | None = SCIMClient.PATCH_RESPONSE_STATUS_CODES,
        raise_scim_errors: bool | None = None,
        *,
        resource: ResourceT | type[ResourceT] | None = None,
        **kwargs: Any,
    ) -> ResourceT | Error | dict[str, Any] | None:
        """Perform a PATCH request to modify a resource, as defined in :rfc:`RFC7644 §3.5.2 <7644#section-3.5.2>`.

        The resource to modify is designated by a resource type and an id, or by a
        :class:`~scim2_models.Resource` object.

        :param target: A :class:`~scim2_models.ResourceType`, or its name or id, or a
            :class:`~scim2_models.Resource` model, which goes to the resource type named after
            its schema. A :class:`~scim2_models.Resource` object stands for both the resource
            type, read from its ``meta.resourceType``, and the id.
        :param id: The id of the resource to modify, or a :class:`~scim2_models.Resource`
            object carrying it. When :paramref:`target` is a :class:`~scim2_models.Resource`
            object, the patch operation may be passed here.
        :param patch_op: The :class:`~scim2_models.PatchOp` object describing the modifications.
            Must be parameterized with the model of the resource
            (e.g., :code:`PatchOp[User]` for a :code:`User`).
        :param resource: Deprecated, pass :paramref:`target` instead.
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
        req = self._prepare_patch_request(
            target=target,
            resource=resource,
            patch_op=patch_op,
            id=id,
            check_request_payload=check_request_payload,
            expected_status_codes=expected_status_codes,
            **kwargs,
        )
        response = await self._send("PATCH", req)
        return cast(
            "ResourceT | Error | dict[str, Any] | None",
            self._read_response(
                response,
                req,
                check_response_payload,
                raise_scim_errors,
                Context.RESOURCE_PATCH_RESPONSE,
            ),
        )

    async def discover(
        self,
        schemas: bool = True,
        resource_types: bool = True,
        service_provider_config: bool = True,
    ) -> None:
        """Dynamically discover the server configuration objects.

        Only what the :attr:`~scim2_client.SCIMClient.provider` does not describe
        yet is queried, so what the client was given takes precedence over what the
        server publishes.

        :param schemas: Whether to discover the :class:`~scim2_models.Schema` endpoint.
        :param resource_types: Whether to discover the :class:`~scim2_models.ResourceType` endpoint.
        :param service_provider_config: Whether to discover the :class:`~scim2_models.ServiceProviderConfig` endpoint.
        :raises ~scim2_client.InvalidServiceDescriptionException: When the objects
            the server publishes do not describe a coherent service.
        """
        queries: dict[type[ScimObject], Awaitable[object]] = {}
        if resource_types and not self._resource_types:
            queries[ResourceType] = self.query(ResourceType, **DISCOVERY_OPTIONS)

        if schemas and not self._models:
            queries[Schema] = self.query(Schema, **DISCOVERY_OPTIONS)

        if service_provider_config and not self._config:
            queries[ServiceProviderConfig] = self.query(
                ServiceProviderConfig, **DISCOVERY_OPTIONS
            )

        # Collecting every outcome retrieves the exceptions of all the queries, so
        # asyncio does not report the ones left behind by the first failure.
        results = await asyncio.gather(*queries.values(), return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException):
                raise result

        published = dict(zip(queries, results, strict=True))

        discovered_resource_types: Collection[ResourceType] = self._resource_types
        if ResourceType in published:
            resource_types_response = cast(
                "ListResponse[ResourceType] | None", published[ResourceType]
            )
            discovered_resource_types = (
                self._published(resource_types_response).resources or []
            )

        discovered_schemas = None
        if Schema in published:
            schemas_response = cast("ListResponse[Schema] | None", published[Schema])
            discovered_schemas = self._published(schemas_response).resources or []

        config = self._config
        if ServiceProviderConfig in published:
            config_response = cast(
                "ServiceProviderConfig | None", published[ServiceProviderConfig]
            )
            config = self._published(config_response)

        self.provider = self._describe_service(
            discovered_schemas, discovered_resource_types, config
        )

    async def request(self, method: str, url: str, **kwargs: Any) -> RawResponse:
        """Send a request to the server, without any SCIM processing.

        Neither the request nor the response is checked, so this is fitted to
        observe how the server behaves, for instance with an unsupported HTTP method.

        :param method: The HTTP method.
        :param url: The URL, relative to the SCIM server base URL.
        :param kwargs: Additional parameters passed to the underlying
            HTTP request library.
        :return: The response of the underlying HTTP request library.
        :raises ~scim2_client.RequestNetworkException: When the request cannot be sent.

        :usage:

        .. code-block:: python
            :caption: Checking that the ``/Schemas`` endpoint refuses ``DELETE``

            response = await scim.request("DELETE", "/Schemas")
            assert response.status_code == 405
        """
        raise NotImplementedError()
