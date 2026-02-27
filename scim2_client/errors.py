import warnings
from typing import Any


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

    This exception is raised when a :class:`httpx.RequestError` has been caught
    while performing a request. The original :class:`~httpx.RequestError` is
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


class ResponsePayloadValidationException(SCIMResponseException):
    """Exception raised when the server returned a payload that cannot be validated.

    This exception is raised when a :class:`pydantic.ValidationError` has been caught
    while validating the server response payload.
    The original :class:`~pydantic.ValidationError` is available with
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


# Deprecated aliases - will be removed in 0.9


class SCIMClientError(SCIMClientException):
    """Deprecated: Use :class:`SCIMClientException` instead."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "SCIMClientError is deprecated, use SCIMClientException instead. "
            "It will be removed in version 0.9.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)


class SCIMResponseError(SCIMResponseException):
    """Deprecated: Use :class:`SCIMResponseException` instead."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "SCIMResponseError is deprecated, use SCIMResponseException instead. "
            "It will be removed in version 0.9.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)


class RequestNetworkError(RequestNetworkException):
    """Deprecated: Use :class:`RequestNetworkException` instead."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "RequestNetworkError is deprecated, use RequestNetworkException instead. "
            "It will be removed in version 0.9.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)


class UnexpectedStatusCode(UnexpectedStatusCodeException):
    """Deprecated: Use :class:`UnexpectedStatusCodeException` instead."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "UnexpectedStatusCode is deprecated, use UnexpectedStatusCodeException "
            "instead. It will be removed in version 0.9.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)


class UnexpectedContentType(UnexpectedContentTypeException):
    """Deprecated: Use :class:`UnexpectedContentTypeException` instead."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "UnexpectedContentType is deprecated, use UnexpectedContentTypeException "
            "instead. It will be removed in version 0.9.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)


class UnexpectedContentFormat(UnexpectedContentFormatException):
    """Deprecated: Use :class:`UnexpectedContentFormatException` instead."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "UnexpectedContentFormat is deprecated, use "
            "UnexpectedContentFormatException instead. "
            "It will be removed in version 0.9.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)


class ResponsePayloadValidationError(ResponsePayloadValidationException):
    """Deprecated: Use :class:`ResponsePayloadValidationException` instead."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "ResponsePayloadValidationError is deprecated, use "
            "ResponsePayloadValidationException instead. "
            "It will be removed in version 0.9.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)
