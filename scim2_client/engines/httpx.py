"""Deprecated alias for :mod:`scim2_client.engines.httpx2`."""

import warnings

from scim2_client.engines.httpx2 import AsyncSCIMClient
from scim2_client.engines.httpx2 import SyncSCIMClient

warnings.warn(
    "'scim2_client.engines.httpx' is deprecated, "
    "use 'scim2_client.engines.httpx2' instead. "
    "Will be removed in 0.9.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["AsyncSCIMClient", "SyncSCIMClient"]
