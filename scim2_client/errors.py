import sys
from typing import Any

from pydantic import ValidationError
from scim2_models import Context
from scim2_models import Error
from scim2_models import SCIMException


class SCIMClientException(Exception):
    """Base exception for scim2-client.

    :param message: The exception reason.
    :param source: The request payload or the response object that have
        caused the exception.
    """

    def __init__(
        self, message: str, source: Any = None, *args: Any, **kwargs: Any
    ) -> None:
        self.message = message
        self.source = source
        super().__init__(*args, **kwargs)

    def __str__(self) -> str:
        return self.message or "UNKNOWN"


class RequestNetworkException(SCIMClientException):
    """Exception raised when a network error happened during request.

    This exception is raised when a :class:`httpx2.RequestError` has been caught
    while performing a request. The original :class:`~httpx2.RequestError` is
    available with :attr:`~BaseException.__cause__`.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        message = kwargs.pop("message", "Network error happened during request")
        super().__init__(message, *args, **kwargs)


class SCIMResponseException(SCIMClientException):
    """Base exception for errors happening during response payload validation."""


class UnexpectedStatusCodeException(SCIMResponseException):
    """Exception raised when a server returned an unexpected status code."""

    def __init__(self, status_code: int, *args: Any, **kwargs: Any) -> None:
        message = kwargs.pop(
            "message", f"Unexpected response status code: {status_code}"
        )
        super().__init__(message, *args, **kwargs)


class UnexpectedContentTypeException(SCIMResponseException):
    """Exception raised when a server returned an unexpected `Content-Type` header."""

    def __init__(self, content_type: str, *args: Any, **kwargs: Any) -> None:
        message = kwargs.pop("message", f"Unexpected content type: {content_type}")
        super().__init__(message, *args, **kwargs)


class UnexpectedContentFormatException(SCIMResponseException):
    """Exception raised when a server returned a response in a non-JSON format."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        message = kwargs.pop("message", "Unexpected response content format")
        super().__init__(message, *args, **kwargs)


class InvalidServiceDescriptionException(SCIMResponseException):
    """Exception raised when a server describes a service that cannot be composed.

    This exception is raised when a :class:`~scim2_models.ScimProviderError` has been
    caught while building the :class:`~scim2_models.ScimProvider` describing the server.
    The original :class:`~scim2_models.ScimProviderError` is available with
    :attr:`~BaseException.__cause__`.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        message = kwargs.pop("message", "Invalid service description")
        super().__init__(message, *args, **kwargs)


class ResponsePayloadValidationException(SCIMResponseException):
    """Exception raised when the server returned a payload that cannot be validated.

    This exception is raised when a :class:`ValidationError <pydantic_core.ValidationError>` has been caught
    while validating the server response payload.
    The original :class:`ValidationError <pydantic_core.ValidationError>` is available with
    :attr:`~BaseException.__cause__`.

    .. code-block:: python

        try:
            scim.query(User, "foobar")
        except ResponsePayloadValidationException as exc:
            print("Original validation error cause", exc.__cause__)
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        message = kwargs.pop("message", "Server response payload validation error")
        super().__init__(message, *args, **kwargs)


def server_error_exception(
    error: Error, scim_ctx: Context | None = None
) -> SCIMException:
    """Build the exception matching an :class:`~scim2_models.Error` object returned by a server.

    The error object is available with the ``error`` attribute, and the raw
    response with the ``source`` attribute.
    """
    exc = SCIMException.from_error(error, scim_ctx=scim_ctx)

    # from_error() rebuilds 'status' and 'scim_type' from the exception class, so
    # anything the server sent that has no matching class is lost. The values that
    # were actually received are restored as instance attributes, which 'to_error()'
    # reads back. This whole function can go once the minimum scim2-models version
    # keeps the error object itself.
    if error.status is not None:
        exc.status = error.status
    exc.scim_type = error.scim_type or ""
    exc.error = error  # type: ignore[attr-defined]
    return exc


def request_validation_exception(
    exc: ValidationError, scim_ctx: Context
) -> SCIMException:
    """Build the exception matching an invalid request payload.

    The original :class:`ValidationError <pydantic_core.ValidationError>` is available with
    :attr:`~BaseException.__cause__`, and describes every invalid attribute.
    """
    errors = Error.from_validation_errors(exc)
    scim_exc = SCIMException.from_error(errors[0], scim_ctx=scim_ctx)
    if sys.version_info >= (3, 11):  # pragma: no cover
        scim_exc.add_note(str(exc))
    return scim_exc
