import importlib
import sys
import warnings

import httpx
import pytest
from scim2_models import ScimProvider
from scim2_models import User

from scim2_client.engines import httpx2 as engine
from scim2_client.engines.httpx2 import AsyncSCIMClient
from scim2_client.engines.httpx2 import SyncSCIMClient
from scim2_client.engines.httpx2 import _request_error_classes
from scim2_client.errors import RequestNetworkException

requires_httpx2 = pytest.mark.skipif(
    engine.Client is httpx.Client, reason="httpx2 is not installed"
)


def test_legacy_engine_module_is_deprecated():
    """Importing scim2_client.engines.httpx emits a deprecation warning."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        legacy = importlib.import_module("scim2_client.engines.httpx")

    with pytest.warns(DeprecationWarning, match="scim2_client.engines.httpx"):
        importlib.reload(legacy)

    assert legacy.SyncSCIMClient is engine.SyncSCIMClient
    assert legacy.AsyncSCIMClient is engine.AsyncSCIMClient


@requires_httpx2
def test_engine_falls_back_on_httpx_when_httpx2_is_missing():
    """The engine imports httpx and warns when httpx2 is unavailable."""
    httpx2 = sys.modules["httpx2"]
    sys.modules["httpx2"] = None
    try:
        with pytest.warns(DeprecationWarning, match="httpx2 is not installed"):
            importlib.reload(engine)

        assert engine.Client is httpx.Client
        assert engine.AsyncClient is httpx.AsyncClient
        assert engine.Response is httpx.Response

    finally:
        sys.modules["httpx2"] = httpx2
        importlib.reload(engine)


@requires_httpx2
def test_httpx_client_is_deprecated(httpserver):
    """Passing a httpx client to the engine emits a deprecation warning."""
    with httpx.Client(base_url=f"http://localhost:{httpserver.port}") as client:
        with pytest.warns(DeprecationWarning, match="httpx client is deprecated"):
            SyncSCIMClient(client, provider=ScimProvider(models=[User]))


@requires_httpx2
async def test_httpx_async_client_is_deprecated(httpserver):
    """Passing a httpx async client to the engine emits a deprecation warning."""
    async with httpx.AsyncClient(
        base_url=f"http://localhost:{httpserver.port}"
    ) as client:
        with pytest.warns(DeprecationWarning, match="httpx client is deprecated"):
            AsyncSCIMClient(client, provider=ScimProvider(models=[User]))


@requires_httpx2
def test_network_errors_of_httpx_clients_are_converted(httpserver):
    """Network errors raised by a httpx client become RequestNetworkException."""
    with httpx.Client(base_url=f"http://localhost:{httpserver.port}") as client:
        with pytest.warns(DeprecationWarning):
            scim_client = SyncSCIMClient(client, provider=ScimProvider(models=[User]))

        with pytest.raises(
            RequestNetworkException, match="Network error happened during request"
        ):
            scim_client.query(url="http://invalid.test")


@requires_httpx2
def test_httpx_clients_are_accepted_when_httpx_is_the_flavor_in_use(
    monkeypatch, httpserver
):
    """A httpx client raises no warning when the engine itself runs on httpx."""
    monkeypatch.setattr(engine, "Client", httpx.Client)
    with httpx.Client(base_url=f"http://localhost:{httpserver.port}") as client:
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            SyncSCIMClient(client, provider=ScimProvider(models=[User]))


def test_client_flavor_is_not_checked_when_httpx_is_not_imported(
    monkeypatch, httpserver
):
    """Clients are not inspected when httpx is absent from the interpreter."""
    monkeypatch.delitem(sys.modules, "httpx", raising=False)
    with engine.Client(base_url=f"http://localhost:{httpserver.port}") as client:
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            SyncSCIMClient(client, provider=ScimProvider(models=[User]))


@requires_httpx2
def test_request_errors_of_every_imported_flavor_are_caught():
    """Every imported httpx flavor contributes its RequestError class."""
    classes = _request_error_classes()
    assert httpx.RequestError in classes
    assert sys.modules["httpx2"].RequestError in classes


def test_request_errors_of_absent_flavors_are_ignored(monkeypatch):
    """A flavor that is not imported contributes no RequestError class."""
    monkeypatch.delitem(sys.modules, "httpx", raising=False)
    assert httpx.RequestError not in _request_error_classes()
