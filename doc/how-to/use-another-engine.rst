Choose or write a request engine
================================

Use this guide to pick the engine that performs the requests, or to write one for an HTTP
library scim2-client does not ship support for. An engine turns the request scim2-client
prepared into a call, and hands the response back for checking; everything else — building the
payloads, validating them, reading the service description — belongs to
:class:`~scim2_client.SCIMClient` and is shared by every engine.

Pick a shipped engine
---------------------

:class:`~scim2_client.engines.httpx2.SyncSCIMClient`
    Performs the requests over the network with `httpx2 <https://github.com/pydantic/httpx2>`_.

:class:`~scim2_client.engines.httpx2.AsyncSCIMClient`
    The same API, awaited. It is the engine an asynchronous application uses.

:class:`~scim2_client.engines.werkzeug.TestSCIMClient`
    Takes a WSGI application and executes the server code directly, without a network. This is
    faster in a test suite, and an exception raised by the server surfaces in the test rather
    than turning into a ``500``.

Test a SCIM server without a network
------------------------------------

:class:`~scim2_client.engines.werkzeug.TestSCIMClient` is meant for the authors of SCIM servers.
It takes a :class:`Werkzeug test Client <werkzeug.test.Client>` wrapping the application, and a
prefix when the SCIM endpoints are not served at the root:

.. code-block:: python

    from scim2_client.engines.werkzeug import TestSCIMClient
    from scim2_models import Group, ScimProvider, User
    from werkzeug.test import Client

    scim = TestSCIMClient(
        Client(myapp.create_app()),
        scim_prefix="/scim/v2",
        provider=ScimProvider(models=[User, Group]),
    )

    user = scim.create(User(user_name="bjensen@example.com"))
    assert user.id

The client checks the payloads the application produces, and a compliance mistake fails the
test.

Write an engine
---------------

An engine inherits :class:`~scim2_client.BaseSyncSCIMClient`, or its asynchronous counterpart,
and implements one method per operation. Each one prepares the request, performs it with the
underlying library, and hands the result to
:meth:`~scim2_client.SCIMClient.check_response`. The engines shipped with scim2-client are the
reference to follow.

Pass parameters to the underlying library
-----------------------------------------

Every method forwards the keyword arguments it does not recognise to the engine, which passes
them to the library performing the request. This is the way to reach a URL the client would not
have built:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          scim.query(url="/User/i-know-what-im-doing")

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          await scim.query(url="/User/i-know-what-im-doing")
