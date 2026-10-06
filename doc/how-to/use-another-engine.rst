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

:class:`~scim2_client.engines.wsgi.WSGISCIMClient`
    Calls a WSGI application directly, without a network. This is faster in a test suite, and an
    exception raised by the server surfaces in the test rather than turning into a ``500``.

:class:`~scim2_client.engines.asgi.ASGISCIMClient`
    The same, awaited, for an ASGI application.

Test a SCIM server without a network
------------------------------------

:class:`~scim2_client.engines.wsgi.WSGISCIMClient` and
:class:`~scim2_client.engines.asgi.ASGISCIMClient` are meant for the authors of SCIM servers. They
only need the standard library, and work with any WSGI or ASGI application, such as a Flask,
Django or Starlette application, or the applications of
`scim2-server <https://scim2-server.readthedocs.io>`_. Pass the application, and the URL of the
SCIM endpoints when they are not served at the root:

.. tab-set::
   :class: outline

   .. tab-item:: WSGI
      :sync: sync

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

   .. tab-item:: ASGI
      :sync: async

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

The client checks the payloads the application produces, and a compliance mistake fails the
test.

The ``headers`` parameter gives headers to send with every request, such as ``Authorization``.
The ``environ`` parameter of the WSGI engine and the ``scope`` parameter of the ASGI engine add
keys to every request, such as ``REMOTE_USER``. The ASGI engine sends no ``lifespan`` message:
start an application that needs them apart.

:class:`~scim2_client.engines.werkzeug.TestSCIMClient`, which needs Werkzeug, is deprecated in
favor of :class:`~scim2_client.engines.wsgi.WSGISCIMClient`.

Write an engine
---------------

An engine inherits :class:`~scim2_client.BaseSyncSCIMClient`, or
:class:`~scim2_client.BaseAsyncSCIMClient` for an asynchronous library, and implements
:meth:`~scim2_client.BaseSyncSCIMClient.request`. This method sends a request
with the underlying library and returns its response. Every operation goes through it.
It receives the query parameters as ``params`` and the JSON body as ``json``, as in httpx and
requests. The response must have the attributes of :class:`~scim2_client.client.RawResponse`.

.. code-block:: python

    import requests
    from scim2_client import BaseSyncSCIMClient

    class RequestsSCIMClient(BaseSyncSCIMClient):
        def __init__(self, base_url, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.base_url = base_url
            self.session = requests.Session()

        def request(self, method, url, **kwargs):
            return self.session.request(method, self.base_url + url, **kwargs)

The engines shipped with scim2-client are the reference to follow.

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
