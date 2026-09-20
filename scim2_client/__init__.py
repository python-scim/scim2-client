from . import errors
from .client import BaseSyncSCIMClient
from .client import SCIMClient
from .errors import RequestNetworkException
from .errors import ResponsePayloadValidationException
from .errors import SCIMClientException
from .errors import SCIMResponseException
from .errors import UnexpectedContentFormatException
from .errors import UnexpectedContentTypeException
from .errors import UnexpectedStatusCodeException

__all__ = [
    "SCIMClient",
    "BaseSyncSCIMClient",
    "SCIMClientException",
    "SCIMResponseException",
    "RequestNetworkException",
    "UnexpectedStatusCodeException",
    "UnexpectedContentTypeException",
    "UnexpectedContentFormatException",
    "ResponsePayloadValidationException",
]


def __getattr__(name: str) -> type[SCIMClientException]:
    if name not in errors._DEPRECATED_ALIASES:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    return errors.deprecated_alias(name)
