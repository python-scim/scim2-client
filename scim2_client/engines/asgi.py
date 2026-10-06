import asyncio
from collections.abc import Awaitable
from collections.abc import Callable
from collections.abc import MutableMapping
from typing import Any
from typing import cast
from urllib.parse import unquote
from wsgiref.headers import Headers

from scim2_client.client import BaseAsyncSCIMClient
from scim2_client.client import RawResponse
from scim2_client.engines.inprocess import InProcessResponse
from scim2_client.engines.inprocess import _check_base_url
from scim2_client.engines.inprocess import _default_port
from scim2_client.engines.inprocess import _HeadersT
from scim2_client.engines.inprocess import _InProcessRequest
from scim2_client.engines.inprocess import _prepare_request
from scim2_client.engines.inprocess import _stays_under_base_url

_Scope = MutableMapping[str, Any]
_Message = MutableMapping[str, Any]
_Receive = Callable[[], Awaitable[_Message]]
_Send = Callable[[_Message], Awaitable[None]]
_ASGIApplication = Callable[[_Scope, _Receive, _Send], Awaitable[None]]


def _build_scope(request: _InProcessRequest, extra: _Scope) -> _Scope:
    """Return the ASGI scope of an HTTP request."""
    url = request.url
    scope: _Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": request.method,
        "scheme": url.scheme,
        "path": unquote(url.path),
        "raw_path": url.path.encode(),
        "query_string": url.query.encode(),
        "root_path": "",
        "headers": [
            (name.lower().encode("latin-1"), value.encode("latin-1"))
            for name, value in request.headers
        ],
        "client": ("127.0.0.1", 123),
        "server": (url.hostname or "", _default_port(url)),
    }
    return {**scope, **extra}


async def _call_application(
    app: _ASGIApplication, scope: _Scope, body: bytes
) -> InProcessResponse:
    """Call an ASGI application, and return its response once its body is sent."""
    started: list[InProcessResponse] = []
    chunks: list[bytes] = []
    request_sent = False
    response_complete = asyncio.Event()

    async def receive() -> _Message:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        # A request is disconnected only once its response is sent, so an
        # application listening for the disconnection, such as a streaming
        # response, is not interrupted.
        await response_complete.wait()
        return {"type": "http.disconnect"}

    async def send(message: _Message) -> None:
        if message["type"] == "http.response.start":
            started[:] = [
                InProcessResponse(
                    status_code=message["status"],
                    headers=Headers(
                        [
                            (name.decode("latin-1"), value.decode("latin-1"))
                            for name, value in message.get("headers", [])
                        ]
                    ),
                )
            ]
            return

        if not started:
            raise RuntimeError(
                "The ASGI application sent a body before starting the response"
            )
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            response_complete.set()

    await app(scope, receive, send)

    if not response_complete.is_set():
        raise RuntimeError("The ASGI application returned before sending its response")

    response = started[0]
    response.content = b"".join(chunks)
    return response


class ASGISCIMClient(BaseAsyncSCIMClient):
    """Call an ASGI application directly, without a network.

    This is helpful for developers of asynchronous SCIM servers. The server code
    runs in the test event loop, so an exception it raises reaches the test
    instead of turning into a ``500`` response. It only needs the standard
    library, and runs with :mod:`asyncio`.

    The ``lifespan`` messages are not sent: an application that needs them
    must be started apart.

    :param app: The ASGI 3 application.
    :param base_url: The absolute URL of the SCIM endpoints, such as ``http://localhost/scim/v2``.
        Its path is passed in the ``path`` of the scope, and ``root_path`` is empty.
    :param headers: Headers sent with every request.
        The headers passed to a request replace those of the same name.
    :param scope: Keys added to the ASGI scope of every request,
        such as ``state`` or ``user``.
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

        from scim2_client.engines.asgi import ASGISCIMClient
        from scim2_models import Group, ScimProvider, User

        scim = ASGISCIMClient(
            myapp.create_app(),
            base_url="http://localhost/scim/v2",
            provider=ScimProvider(models=[User, Group]),
        )

        user = await scim.create(User(user_name="bjensen@example.com"))
        assert user.id
    """

    def __init__(
        self,
        app: _ASGIApplication,
        base_url: str = "http://localhost",
        headers: _HeadersT | None = None,
        scope: _Scope | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.app = app
        self.base_url = _check_base_url(base_url)
        self.headers = headers
        self.scope = scope or {}

    def _stays_under_base_url(self, endpoint: str) -> bool:
        return _stays_under_base_url(self.base_url, endpoint)

    def _parse_json(self, response: RawResponse) -> Any:
        return cast(InProcessResponse, response).json()

    async def request(self, method: str, url: str, **kwargs: Any) -> InProcessResponse:
        request = _prepare_request(self.base_url, self.headers, method, url, **kwargs)
        return await _call_application(
            self.app, _build_scope(request, self.scope), request.body
        )
