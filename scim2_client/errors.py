from typing import TYPE_CHECKING
from typing import Any

if TYPE_CHECKING:
    from scim2_models import Error


class SCIMClientError(Exception):
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


class SCIMRequestError(SCIMClientError):
    """Base exception for errors happening during request payload building."""


class RequestNetworkError(SCIMRequestError):
    """Error raised when a network error happened during request.

    This error is raised when a :class:`httpx.RequestError` has been caught while performing a request.
    The original :class:`~httpx.RequestError` is available with :attr:`~BaseException.__cause__`.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        message = kwargs.pop("message", "Network error happened during request")
        super().__init__(message, *args, **kwargs)


class RequestPayloadValidationError(SCIMRequestError):
    """Error raised when an invalid request payload has been passed to SCIMClient.

    This error is raised when a :class:`pydantic.ValidationError` has been caught
    while validating the client request payload.
    The original :class:`~pydantic.ValidationError` is available with :attr:`~BaseException.__cause__`.

    .. code-block:: python

        try:
            scim.create(
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "active": "not-a-bool",
                }
            )
        except RequestPayloadValidationError as exc:
            print("Original validation error cause", exc.__cause__)
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        message = kwargs.pop("message", "Server request payload validation error")
        super().__init__(message, *args, **kwargs)


class SCIMResponseError(SCIMClientError):
    """Base exception for errors happening during response payload validation."""


class SCIMResponseErrorObject(SCIMResponseError):
    """The server response returned a :class:`scim2_models.Error` object.

    Those errors are only raised when the :code:`raise_scim_errors` parameter is :data:`True`.

    :param error: The :class:`~scim2_models.Error` object returned by the server.
    """

    def __init__(self, error: "Error", *args: Any, **kwargs: Any) -> None:
        self._error = error
        parts = []
        if error.scim_type:
            parts.append(error.scim_type + ":")
        if error.detail:
            parts.append(error.detail)
        message = " ".join(parts) if parts else "SCIM Error"
        super().__init__(message, *args, **kwargs)

    def to_error(self) -> "Error":
        """Return the :class:`~scim2_models.Error` object returned by the server."""
        return self._error


class UnexpectedStatusCode(SCIMResponseError):
    """Error raised when a server returned an unexpected status code for a given :class:`~scim2_models.Context`."""

    def __init__(self, status_code: int, *args: Any, **kwargs: Any) -> None:
        message = kwargs.pop(
            "message", f"Unexpected response status code: {status_code}"
        )
        super().__init__(message, *args, **kwargs)


class UnexpectedContentType(SCIMResponseError):
    """Error raised when a server returned an unexpected `Content-Type` header in a response."""

    def __init__(self, content_type: str, *args: Any, **kwargs: Any) -> None:
        message = kwargs.pop("message", f"Unexpected content type: {content_type}")
        super().__init__(message, *args, **kwargs)


class UnexpectedContentFormat(SCIMResponseError):
    """Error raised when a server returned a response in a non-JSON format."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        message = kwargs.pop("message", "Unexpected response content format")
        super().__init__(message, *args, **kwargs)


class ResponsePayloadValidationError(SCIMResponseError):
    """Error raised when the server returned a payload that cannot be validated.

    This error is raised when a :class:`pydantic.ValidationError` has been caught
    while validating the server response payload.
    The original :class:`~pydantic.ValidationError` is available with :attr:`~BaseException.__cause__`.

    .. code-block:: python

        try:
            scim.query(User, "foobar")
        except ResponsePayloadValidationError as exc:
            print("Original validation error cause", exc.__cause__)
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        message = kwargs.pop("message", "Server response payload validation error")
        super().__init__(message, *args, **kwargs)
