from .client import BaseSyncSCIMClient
from .client import SCIMClient
from .errors import RequestNetworkError
from .errors import RequestNetworkException
from .errors import ResponsePayloadValidationError
from .errors import ResponsePayloadValidationException
from .errors import SCIMClientError
from .errors import SCIMClientException
from .errors import SCIMResponseError
from .errors import SCIMResponseException
from .errors import UnexpectedContentFormat
from .errors import UnexpectedContentFormatException
from .errors import UnexpectedContentType
from .errors import UnexpectedContentTypeException
from .errors import UnexpectedStatusCode
from .errors import UnexpectedStatusCodeException

__all__ = [
    "SCIMClient",
    "BaseSyncSCIMClient",
    # New exception classes
    "SCIMClientException",
    "SCIMResponseException",
    "RequestNetworkException",
    "UnexpectedStatusCodeException",
    "UnexpectedContentTypeException",
    "UnexpectedContentFormatException",
    "ResponsePayloadValidationException",
    # Deprecated aliases (will be removed in 0.9)
    "SCIMClientError",
    "SCIMResponseError",
    "RequestNetworkError",
    "UnexpectedStatusCode",
    "UnexpectedContentType",
    "UnexpectedContentFormat",
    "ResponsePayloadValidationError",
]
