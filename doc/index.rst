scim2-client
============

scim2-client builds the requests of the SCIM protocol and reads the responses to them,
following :rfc:`RFC7643 <7643>` and :rfc:`RFC7644 <7644>`. It represents the payloads as
`scim2-models <https://scim2-models.readthedocs.io>`_ objects, and hands the HTTP request
itself to an engine, so an application talks to a SCIM server in Python rather than in JSON.

.. code-block:: python

    from httpx2 import Client
    from scim2_client.engines.httpx2 import SyncSCIMClient

    client = Client(
        base_url="https://auth.example/scim/v2",
        headers={"Authorization": "Bearer foobar"},
    )
    scim = SyncSCIMClient(client)
    scim.discover()

    User = scim.get_resource_model("User")
    user = scim.query(User, "2819c223-7f76-453a-919d-413861904646")
    user.display_name = "Babs Jensen"
    user = scim.replace(user)

It performs no network call of its own, holds no credentials and retries nothing: those belong
to the engine and to the application that configures it. It suits a SCIM client application, and
the test suite of a SCIM server.

.. code-block:: shell

   pip install scim2-client[httpx2]

Choose a path
-------------

:doc:`Overview <overview>` gives a broad tour of the operations a SCIM client performs.

:doc:`How-to guides <how-to/index>` show how to complete a specific task, such as versioning
resources with ETags or talking to a server that departs from the specifications.

:doc:`Explanation <explanation/index>` gives the reasons behind the behaviour of the library:
what it checks in a payload, and what it needs to know about a server.

:doc:`Reference <reference>` lists the complete public API.

.. toctree::
    :maxdepth: 2
    :hidden:

    Overview <overview>
    How-to guides <how-to/index>
    Explanation <explanation/index>
    Reference <reference>
    Contributing <contributing>
    Changelog <changelog>
