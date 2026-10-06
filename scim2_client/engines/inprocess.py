"""The parts of the WSGI and ASGI engines that do not depend on the protocol."""

import json as jsonlib
from collections.abc import Iterable
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from urllib.parse import SplitResult
from urllib.parse import urlencode
from urllib.parse import urljoin
from urllib.parse import urlsplit
from wsgiref.headers import Headers

_HeadersT = Mapping[str, str] | Iterable[tuple[str, str]]


@dataclass
class InProcessResponse:
    """The response of an application called by an in-process engine.

    It has the attributes of :class:`~scim2_client.client.RawResponse`.
    """

    status_code: int
    """The HTTP status code."""

    headers: Headers = field(default_factory=lambda: Headers([]))
    """The HTTP headers. Their names are case insensitive."""

    content: bytes = b""
    """The raw body."""

    @property
    def text(self) -> str:
        """The body, decoded as UTF-8 (:rfc:`8259#section-8.1`)."""
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        """Return the body, decoded as JSON."""
        return jsonlib.loads(self.content)


@dataclass
class _InProcessRequest:
    """A request ready to be passed to an application."""

    method: str
    url: SplitResult
    headers: list[tuple[str, str]]
    body: bytes


def _header_pairs(headers: _HeadersT | None) -> list[tuple[str, str]]:
    if headers is None:
        return []
    if isinstance(headers, Mapping):
        return list(headers.items())
    return list(headers)


def _merge_headers(
    defaults: _HeadersT | None, overrides: _HeadersT | None
) -> list[tuple[str, str]]:
    """Return the default headers, replaced by the overriding headers of the same name."""
    pairs = _header_pairs(overrides)
    names = {name.lower() for name, _ in pairs}
    kept = [pair for pair in _header_pairs(defaults) if pair[0].lower() not in names]
    return kept + pairs


def _check_base_url(base_url: str) -> str:
    parts = urlsplit(base_url)
    if not parts.scheme or not parts.netloc:
        raise ValueError(f"The base URL '{base_url}' is not absolute")
    return base_url


def _build_url(base_url: str, url: str) -> SplitResult:
    """Return the URL a request is sent to, with its dot segments resolved.

    A relative URL is appended to the path of the base URL, as httpx does.
    """
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in url):
        raise ValueError(f"The URL {url!r} has control characters")

    if not urlsplit(url).scheme:
        base_path = urlsplit(base_url).path.rstrip("/")
        url = f"{base_path}/{url.lstrip('/')}"
    return urlsplit(urljoin(base_url, url))


def _default_port(url: SplitResult) -> int:
    return url.port or (443 if url.scheme == "https" else 80)


def _origin(url: SplitResult) -> tuple[str, str | None, int]:
    return url.scheme, url.hostname, _default_port(url)


def _stays_under_base_url(base_url: str, endpoint: str) -> bool:
    """Tell whether the URL built for an endpoint has the origin and the path prefix of the base URL."""
    base = urlsplit(base_url)
    try:
        url = _build_url(base_url, endpoint)
        same_origin = _origin(url) == _origin(base)
    except ValueError:
        return False

    prefix = f"{base.path.rstrip('/')}/"
    return same_origin and f"{url.path.rstrip('/')}/".startswith(prefix)


def _prepare_request(
    base_url: str,
    default_headers: _HeadersT | None,
    method: str,
    url: str,
    *,
    params: Mapping[str, Any] | None = None,
    json: Any = None,
    content: bytes | None = None,
    headers: _HeadersT | None = None,
) -> _InProcessRequest:
    """Build a request from the arguments of the request method of an engine.

    The parameters are those of httpx: ``params`` for the query string,
    ``json`` or ``content`` for the body, and ``headers``.
    """
    if json is not None and content is not None:
        raise TypeError("Pass either 'json' or 'content', not both")

    target = _build_url(base_url, url)
    if params:
        query = urlencode(params, doseq=True)
        target = target._replace(
            query=f"{target.query}&{query}" if target.query else query
        )

    pairs = [("Host", target.netloc)]
    body = content or b""
    if json is not None:
        body = jsonlib.dumps(json).encode()
        pairs.append(("Content-Type", "application/json"))
    if body:
        pairs.append(("Content-Length", str(len(body))))

    return _InProcessRequest(
        method=method.upper(),
        url=target,
        headers=_merge_headers(_merge_headers(pairs, default_headers), headers),
        body=body,
    )
