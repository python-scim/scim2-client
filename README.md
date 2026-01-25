# scim2-client

A SCIM client Python library built upon [scim2-models](https://scim2-models.readthedocs.io) ,
that pythonically build requests and parse responses,
following the [RFC7643](https://datatracker.ietf.org/doc/html/rfc7643.html) and [RFC7644](https://datatracker.ietf.org/doc/html/rfc7644.html) specifications.
You can use whatever request engine you prefer to perform network requests, but scim2-client comes with [httpx](https://github.com/encode/httpx) support.

It aims to be used in SCIM client applications, or in unit tests for SCIM server applications.

## What's SCIM anyway?

SCIM stands for System for Cross-domain Identity Management, and it is a provisioning protocol.
Provisioning is the action of managing a set of resources across different services, usually users and groups.
SCIM is often used between Identity Providers and applications in completion of standards like OAuth2 and OpenID Connect.
It allows users and groups creations, modifications and deletions to be synchronized between applications.

## Features

- **CRUD Operations**: `create`, `query`, `replace`, `delete` methods for SCIM resources
- **PATCH Support**: Partial resource modifications with `add`, `remove` and `replace` operations
- **Server Discovery**: Automatic retrieval of `ServiceProviderConfig`, `ResourceTypes` and `Schemas`
- **Search & Filtering**: Support for SCIM filters, sorting, pagination and attribute selection
- **Sync & Async**: Both synchronous and asynchronous clients available
- **Multiple HTTP Engines**: Built-in support for [httpx](https://github.com/encode/httpx) (sync/async) and [werkzeug](https://werkzeug.palletsprojects.com/) (testing)
- **Request & Response Validation**: Automatic payload validation against SCIM schemas
- **Error Handling**: Structured exceptions for network, request and response errors

## Installation

```shell
pip install scim2-client[httpx]
```

## Usage

Check the [tutorial](https://scim2-client.readthedocs.io/en/latest/tutorial.html)
and the [reference](https://scim2-client.readthedocs.io/en/latest/reference.html) for more details.

Here is an example of usage:

```python
import datetime
from httpx import Client
from scim2_models import Error
from scim2_client.engines.httpx import SyncSCIMClient

client = Client(base_url="https://auth.example/scim/v2", headers={"Authorization": "Bearer foobar"})
scim = SyncSCIMClient(client)
scim.discover()
User = scim.get_resource_model("User")

# Query resources
user = scim.query(User, "2819c223-7f76-453a-919d-413861904646")
assert user.user_name == "bjensen@example.com"
assert user.meta.last_updated == datetime.datetime(
    2024, 4, 13, 12, 0, 0, tzinfo=datetime.timezone.utc
)

# Update resources
user.display_name = "Babs Jensen"
user = scim.replace(user)
assert user.display_name == "Babs Jensen"
assert user.meta.last_updated == datetime.datetime(
    2024, 4, 13, 12, 0, 30, tzinfo=datetime.timezone.utc
)

# Create resources
payload = User(user_name="bjensen@example.com")
response = scim.create(user)
assert isinstance(response, Error)
assert response.detail == "One or more of the attribute values are already in use or are reserved."
```

scim2-client belongs in a collection of SCIM tools developed by [Yaal Coop](https://yaal.coop),
with [scim2-models](https://github.com/python-scim/scim2-models),
[scim2-tester](https://github.com/python-scim/scim2-tester) and
[scim2-cli](https://github.com/python-scim/scim2-cli)
