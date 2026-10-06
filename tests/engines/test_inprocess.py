import pytest

from scim2_client.engines.inprocess import InProcessResponse
from scim2_client.engines.inprocess import _build_url
from scim2_client.engines.inprocess import _check_base_url
from scim2_client.engines.inprocess import _prepare_request

BASE_URL = "http://scim.test/scim/v2"


def test_response_text_is_decoded_as_utf8():
    """The body is read as UTF-8, and undecodable bytes are replaced."""
    response = InProcessResponse(200, content="é".encode() + b"\xff")

    assert response.text == "é�"


def test_response_json_decodes_the_body():
    """The body is decoded as JSON, as httpx does."""
    response = InProcessResponse(200, content=b'{"id": "1"}')

    assert response.json() == {"id": "1"}


def test_response_headers_are_case_insensitive():
    """A header is found whatever the case of its name."""
    response = InProcessResponse(200)
    response.headers["Content-Type"] = "application/scim+json"

    assert response.headers.get("content-type") == "application/scim+json"


@pytest.mark.parametrize("base_url", ["/scim/v2", "scim.test/scim/v2", ""])
def test_relative_base_url_is_refused(base_url):
    """The base URL gives the host and the scheme of the requests, so it must be absolute."""
    with pytest.raises(ValueError, match="is not absolute"):
        _check_base_url(base_url)


@pytest.mark.parametrize(
    "base_url,url,expected",
    [
        (BASE_URL, "/Users", "http://scim.test/scim/v2/Users"),
        (BASE_URL, "Users", "http://scim.test/scim/v2/Users"),
        (f"{BASE_URL}/", "/Users", "http://scim.test/scim/v2/Users"),
        ("http://scim.test", "/Users", "http://scim.test/Users"),
        (BASE_URL, "/Users/../Groups", "http://scim.test/scim/v2/Groups"),
        (BASE_URL, "/Users?count=1", "http://scim.test/scim/v2/Users?count=1"),
        (BASE_URL, "https://other.test/Users", "https://other.test/Users"),
    ],
)
def test_url_is_built_under_the_base_url(base_url, url, expected):
    """A relative URL is appended to the path of the base URL, an absolute one is kept."""
    assert _build_url(base_url, url).geturl() == expected


def test_url_with_control_characters_is_refused():
    """A control character cannot be sent in a request line."""
    with pytest.raises(ValueError, match="control characters"):
        _build_url(BASE_URL, "/Users\r\nX-Injected: 1")


def test_params_are_appended_to_the_query_of_the_url():
    """The query parameters extend the query string already in the URL."""
    request = _prepare_request(
        BASE_URL, None, "GET", "/Users?count=1", params={"startIndex": 2}
    )

    assert request.url.query == "count=1&startIndex=2"


def test_params_make_the_query_of_a_url_without_one():
    """The query parameters are encoded in the query string."""
    request = _prepare_request(
        BASE_URL, None, "GET", "/Users", params={"filter": 'userName eq "a b"'}
    )

    assert request.url.query == "filter=userName+eq+%22a+b%22"


def test_json_body_is_encoded_with_its_content_type():
    """A JSON body is sent with its type and its length."""
    request = _prepare_request(BASE_URL, None, "post", "/Users", json={"id": "1"})

    assert request.method == "POST"
    assert request.body == b'{"id": "1"}'
    assert request.headers == [
        ("Host", "scim.test"),
        ("Content-Type", "application/json"),
        ("Content-Length", "11"),
    ]


def test_raw_content_is_sent_as_is():
    """A raw body is sent without content type, so that a test controls it."""
    request = _prepare_request(BASE_URL, None, "POST", "/Users", content=b"not json")

    assert request.body == b"not json"
    assert request.headers == [("Host", "scim.test"), ("Content-Length", "8")]


def test_json_and_content_cannot_be_both_passed():
    """A request has a single body."""
    with pytest.raises(TypeError, match="either 'json' or 'content'"):
        _prepare_request(BASE_URL, None, "POST", "/Users", json={}, content=b"{}")


def test_unknown_request_argument_is_refused():
    """An argument the engine does not know is not silently ignored."""
    with pytest.raises(TypeError):
        _prepare_request(BASE_URL, None, "GET", "/Users", timeout=1)


def test_request_headers_replace_default_headers_of_the_same_name():
    """The headers of a request replace the default headers, whatever the case of their name."""
    request = _prepare_request(
        BASE_URL,
        [("X-Test", "foo"), ("X-Other", "bar"), ("x-test", "baz")],
        "GET",
        "/Users",
        headers={"x-TEST": "qux"},
    )

    assert request.headers == [
        ("Host", "scim.test"),
        ("X-Other", "bar"),
        ("x-TEST", "qux"),
    ]


def test_host_header_can_be_replaced():
    """The Host header comes from the URL, unless the headers give another one."""
    request = _prepare_request(BASE_URL, {"host": "proxy.test"}, "GET", "/Users")

    assert request.headers == [("host", "proxy.test")]
