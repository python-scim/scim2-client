from typing import Any
from typing import cast
from urllib.parse import urlencode

from werkzeug.datastructures import Headers
from werkzeug.test import Client
from werkzeug.test import TestResponse

from scim2_client.client import BaseSyncSCIMClient
from scim2_client.client import RawResponse


class TestSCIMClient(BaseSyncSCIMClient):
    """A client based on :class:`Werkzeug test Client <werkzeug.test.Client>` for application development purposes.

    This is helpful for developers of SCIM servers.
    This client avoids to perform real HTTP requests and directly execute the server code instead.
    This allows to dynamically catch the exceptions if something gets wrong.

    :param client: An optional custom :class:`Werkzeug test Client <werkzeug.test.Client>`.
        If :data:`None` a default client is initialized.
    :param scim_prefix: The scim root endpoint in the application.
    :param environ: Additional parameters that will be passed to every request.
    :param provider: The :class:`~scim2_models.ScimProvider` describing the server.
        If a request payload describe a resource it does not know, an exception will be raised.
        The :class:`~scim2_models.ScimPolicy` it carries rules how much the payloads
        exchanged with the server may depart from the specification.
    :param resource_models: Deprecated, pass a :paramref:`provider` instead.
    :param check_request_payload: If :data:`False`,
        :code:`resource` is expected to be a dict that will be passed as-is in the request.
        This value can be overwritten in methods.
    :param check_response_payload: Whether to validate that the response payloads are valid.
        If set, the raw payload will be returned. This value can be overwritten in methods.
    :param raise_scim_errors: If :data:`True` and the server returned an
        :class:`~scim2_models.Error` object during a request, a :class:`~scim2_models.SCIMException`
        exception will be raised. If :data:`False` the error object is returned. This value can be overwritten in methods.

    .. code-block:: python

        from scim2_client.engines.werkzeug import TestSCIMClient
        from scim2_models import User, Group
        from werkzeug.test import Client

        scim_provider = myapp.create_app()
        testclient = TestSCIMClient(
            app=Client(scim_provider),
            environ={"base_url": "/scim/v2"},
            resource_models=(User, Group),
        )

        request_user = User(user_name="foo", display_name="bar")
        response_user = scim_client.create(request_user)
        assert response_user.user_name == "foo"
    """

    # avoid making Pytest believe this is a test class
    __test__ = False

    def __init__(
        self,
        client: Client,
        environ: dict[str, Any] | None = None,
        scim_prefix: str = "",
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.client = client
        self.scim_prefix = scim_prefix
        self.environ = environ or {}

    def _make_url(self, url: str) -> str:
        prefix = (
            self.scim_prefix[:-1]
            if self.scim_prefix.endswith("/")
            else self.scim_prefix
        )
        return (
            url
            if url.startswith("http://") or url.startswith("https://")
            else f"{prefix}{url}"
        )

    def _parse_json(self, response: RawResponse) -> Any:
        return cast(TestResponse, response).json

    def _query_kwargs(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"query_string": urlencode(payload, doseq=True)}

    def request(self, method: str, url: str, **kwargs: Any) -> TestResponse:
        environ = {**self.environ, **kwargs}
        if "headers" in self.environ and "headers" in kwargs:
            headers = Headers(self.environ["headers"])
            headers.update(Headers(kwargs["headers"]))
            environ["headers"] = headers
        return self.client.open(self._make_url(url), method=method, **environ)
