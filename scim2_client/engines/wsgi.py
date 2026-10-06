import sys
from collections.abc import Callable
from collections.abc import Iterable
from io import BytesIO
from typing import TYPE_CHECKING
from typing import Any
from typing import cast
from urllib.parse import unquote_to_bytes
from wsgiref.headers import Headers

from scim2_client.client import BaseSyncSCIMClient
from scim2_client.client import RawResponse
from scim2_client.engines.inprocess import InProcessResponse
from scim2_client.engines.inprocess import _check_base_url
from scim2_client.engines.inprocess import _default_port
from scim2_client.engines.inprocess import _HeadersT
from scim2_client.engines.inprocess import _InProcessRequest
from scim2_client.engines.inprocess import _prepare_request
from scim2_client.engines.inprocess import _stays_under_base_url

if TYPE_CHECKING:
    from _typeshed import OptExcInfo
    from _typeshed.wsgi import WSGIApplication
    from _typeshed.wsgi import WSGIEnvironment


def _build_environ(
    request: _InProcessRequest, extra: "WSGIEnvironment"
) -> "WSGIEnvironment":
    """Return the WSGI environment of a request (PEP 3333)."""
    url = request.url
    environ: WSGIEnvironment = {
        "REQUEST_METHOD": request.method,
        "SCRIPT_NAME": "",
        # PEP 3333 passes the bytes of the path as a latin-1 string.
        "PATH_INFO": unquote_to_bytes(url.path).decode("latin-1"),
        "QUERY_STRING": url.query,
        "SERVER_NAME": url.hostname or "",
        "SERVER_PORT": str(_default_port(url)),
        "SERVER_PROTOCOL": "HTTP/1.1",
        "REMOTE_ADDR": "127.0.0.1",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": url.scheme,
        "wsgi.input": BytesIO(request.body),
        "wsgi.errors": sys.stderr,
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }
    for name, value in request.headers:
        key = name.upper().replace("-", "_")
        if key not in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            key = f"HTTP_{key}"
        environ[key] = f"{environ[key]}, {value}" if key in environ else value
    return {**environ, **extra}


def _call_application(
    app: "WSGIApplication", environ: "WSGIEnvironment"
) -> InProcessResponse:
    """Call a WSGI application, and return its response once its body is read."""
    started: list[tuple[str, list[tuple[str, str]]]] = []
    chunks: list[bytes] = []

    def start_response(
        status: str,
        headers: list[tuple[str, str]],
        exc_info: "OptExcInfo | None" = None,
    ) -> Callable[[bytes], object]:
        # The response is sent once the application returns, so headers set
        # again after an error replace the previous ones (PEP 3333).
        started[:] = [(status, headers)]
        return chunks.append

    result: Iterable[bytes] = app(environ, start_response)
    try:
        chunks.extend(result)
    finally:
        close = getattr(result, "close", None)
        if close is not None:
            close()

    if not started:
        raise RuntimeError("The WSGI application did not call 'start_response'")

    status, headers = started[0]
    return InProcessResponse(
        status_code=int(status.split(" ", 1)[0]),
        headers=Headers(headers),
        content=b"".join(chunks),
    )


class WSGISCIMClient(BaseSyncSCIMClient):
    """Call a WSGI application directly, without a network.

    This is helpful for developers of SCIM servers. The server code runs in the
    test process, so an exception it raises reaches the test instead of turning
    into a ``500`` response. It only needs the standard library.

    :param app: The WSGI application (:pep:`3333`).
    :param base_url: The absolute URL of the SCIM endpoints, such as ``http://localhost/scim/v2``.
        Its path is passed in ``PATH_INFO``, and ``SCRIPT_NAME`` is empty.
    :param headers: Headers sent with every request.
        The headers passed to a request replace those of the same name.
    :param environ: Keys added to the WSGI environment of every request,
        such as ``REMOTE_USER``.
    :param provider: The :class:`~scim2_models.ScimProvider` describing the server.
        If a request payload describe a resource it does not know, an exception will be raised.
        The :class:`~scim2_models.ScimPolicy` it carries rules how much the payloads
        exchanged with the server may depart from the specification.
    :param check_request_payload: If :data:`False`,
        :code:`resource` is expected to be a dict that will be passed as-is in the request.
        This value can be overwritten in methods.
    :param check_response_payload: Whether to validate that the response payloads are valid.
        If set, the raw payload will be returned. This value can be overwritten in methods.
    :param raise_scim_errors: If :data:`True` and the server returned an
        :class:`~scim2_models.Error` object during a request, a :class:`~scim2_models.SCIMException`
        exception will be raised. If :data:`False` the error object is returned. This value can be overwritten in methods.

    .. code-block:: python

        from scim2_client.engines.wsgi import WSGISCIMClient
        from scim2_models import Group, ScimProvider, User

        scim = WSGISCIMClient(
            myapp.create_app(),
            base_url="http://localhost/scim/v2",
            provider=ScimProvider(models=[User, Group]),
        )

        user = scim.create(User(user_name="bjensen@example.com"))
        assert user.id
    """

    def __init__(
        self,
        app: "WSGIApplication",
        base_url: str = "http://localhost",
        headers: _HeadersT | None = None,
        environ: "WSGIEnvironment | None" = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.app = app
        self.base_url = _check_base_url(base_url)
        self.headers = headers
        self.environ = environ or {}

    def _stays_under_base_url(self, endpoint: str) -> bool:
        return _stays_under_base_url(self.base_url, endpoint)

    def _parse_json(self, response: RawResponse) -> Any:
        return cast(InProcessResponse, response).json()

    def request(self, method: str, url: str, **kwargs: Any) -> InProcessResponse:
        request = _prepare_request(self.base_url, self.headers, method, url, **kwargs)
        return _call_application(self.app, _build_environ(request, self.environ))
