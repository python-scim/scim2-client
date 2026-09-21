Overview
========

scim2-client builds the requests of the **System for Cross-domain Identity Management**
(**SCIM**) protocol and reads the responses to them. It represents the payloads with
`scim2-models <https://scim2-models.readthedocs.io>`_, and hands the HTTP request itself to an
engine.

It performs no network call of its own, holds no credentials, and retries nothing: those belong
to the engine and to the application that configures it.

The :rfc:`SCIM data model <7643>` and :rfc:`SCIM protocol <7644>` specifications define the
vocabulary used here.

Install scim2-client with the engine it will use:

.. code-block:: shell

   pip install scim2-client[httpx2]

This page introduces the operations a client performs, in the order an application meets them.
Follow it in order for a first tour. The :doc:`how-to guides <how-to/index>` cover focused tasks,
the :doc:`explanations <explanation/index>` cover what the client checks and what it needs to
know about a server, and the :doc:`reference` lists the complete API.

Instantiate a client
--------------------

An engine performs the requests. The one shipped with scim2-client is built upon
`httpx2 <https://github.com/pydantic/httpx2>`_, and comes in a synchronous and an asynchronous
flavour. Both take a configured client, which is where the server root endpoint and the
authorization headers belong:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          from httpx2 import Client
          from scim2_client.engines.httpx2 import SyncSCIMClient

          client = Client(
              base_url="https://auth.example/scim/v2",
              headers={"Authorization": "Bearer foobar"},
          )
          scim = SyncSCIMClient(client)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          from httpx2 import AsyncClient
          from scim2_client.engines.httpx2 import AsyncSCIMClient

          client = AsyncClient(
              base_url="https://auth.example/scim/v2",
              headers={"Authorization": "Bearer foobar"},
          )
          scim = AsyncSCIMClient(client)

The two have the same API, and every example below shows both.
:doc:`how-to/use-another-engine` covers the engine serving a WSGI application without a network,
and how to write one for another HTTP library.

.. note::

   The engines still work with `httpx <https://github.com/encode/httpx>`_, shipped in the
   deprecated ``httpx`` extra. It is used when httpx2 is not installed, and both its extra and
   its support will be removed in 0.9. An application that cannot migrate all its dependencies
   at once can call :code:`httpx2.alias_httpx()` at the very top of its entrypoint, so that
   :code:`import httpx` resolves to httpx2 process-wide.

Describe the server
-------------------

A client needs to know which resources the server serves, under which endpoints, and what it is
capable of. A :class:`~scim2_models.ScimProvider` gathers the three, and
:meth:`~scim2_client.BaseSyncSCIMClient.discover` fills it from the endpoints the server
publishes:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          scim.discover()
          User = scim.get_resource_model("User")

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          await scim.discover()
          User = scim.get_resource_model("User")

The models are built from the schemas the server publishes, so they carry the attributes that
server actually declares. :doc:`how-to/describe-the-server` covers describing a server by hand,
and :doc:`explanation/service-description` covers what each part of the description is used for.

Create a resource
-----------------

:meth:`~scim2_client.BaseSyncSCIMClient.create` issues a ``POST`` and returns the resource the
server stored, with the attributes it filled:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          request = User(user_name="bjensen@example.com")
          response = scim.create(request)
          print(f"User {response.id} has been created!")

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          request = User(user_name="bjensen@example.com")
          response = await scim.create(request)
          print(f"User {response.id} has been created!")

Read a resource
---------------

:meth:`~scim2_client.BaseSyncSCIMClient.query` issues a ``GET``. It reads one resource,
designated either by a model and an id or by an object carrying that id, and it lists the
resources of a type when given no id:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          from scim2_models import SearchRequest

          user = scim.query(User, "my-user-id")
          user = scim.query(User(id="my-user-id"))

          response = scim.query(User, query_parameters=SearchRequest(filter='userName sw "john"'))
          for user in response.resources:
              print(user.user_name)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          from scim2_models import SearchRequest

          user = await scim.query(User, "my-user-id")
          user = await scim.query(User(id="my-user-id"))

          response = await scim.query(
              User, query_parameters=SearchRequest(filter='userName sw "john"')
          )
          for user in response.resources:
              print(user.user_name)

A listing returns a :class:`~scim2_models.ListResponse`, whose ``resources`` attribute holds the
objects. The ``query_parameters`` argument carries the filter, the sorting, the paging and the
attribute projection :rfc:`RFC7644 §3.4.2 <7644#section-3.4.2>` defines.

Search across resource types
----------------------------

:meth:`~scim2_client.BaseSyncSCIMClient.search` issues a ``POST`` on the ``/.search`` endpoint,
which queries every resource type at once and takes its parameters in the request body rather
than in the query string:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          response = scim.search(SearchRequest(filter='id co "admin"'))

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          response = await scim.search(SearchRequest(filter='id co "admin"'))

Replace a resource
------------------

:meth:`~scim2_client.BaseSyncSCIMClient.replace` issues a ``PUT``, which overwrites a resource
with the object it is given:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          user = scim.query(User, "my-user-id")
          user.display_name = "Fancy New Name"
          updated_user = scim.replace(user)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          user = await scim.query(User, "my-user-id")
          user.display_name = "Fancy New Name"
          updated_user = await scim.replace(user)

Patch a resource
----------------

:meth:`~scim2_client.BaseSyncSCIMClient.modify` issues a ``PATCH``, which carries the
modifications rather than the whole resource, as :rfc:`RFC7644 §3.5.2 <7644#section-3.5.2>`
defines them:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          from scim2_models import PatchOp, PatchOperation

          patch = PatchOp[User](
              operations=[
                  PatchOperation(
                      op=PatchOperation.Op.replace_, path="displayName", value="New Name"
                  ),
                  PatchOperation(
                      op=PatchOperation.Op.add,
                      path="emails",
                      value=[{"value": "new@example.com"}],
                  ),
              ]
          )
          user = scim.query(User, "my-user-id")
          response = scim.modify(user, patch)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          from scim2_models import PatchOp, PatchOperation

          patch = PatchOp[User](
              operations=[
                  PatchOperation(
                      op=PatchOperation.Op.replace_, path="displayName", value="New Name"
                  ),
                  PatchOperation(
                      op=PatchOperation.Op.add,
                      path="emails",
                      value=[{"value": "new@example.com"}],
                  ),
              ]
          )
          user = await scim.query(User, "my-user-id")
          response = await scim.modify(user, patch)

A server may answer a patch with the modified resource or with an empty ``204``, so ``response``
is :data:`None` when it returned nothing.

Delete a resource
-----------------

:meth:`~scim2_client.BaseSyncSCIMClient.delete` issues a ``DELETE`` and returns :data:`None` on
success:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          scim.delete(User, "my-user-id")

          user = scim.query(User, "my-user-id")
          scim.delete(user)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          await scim.delete(User, "my-user-id")

          user = await scim.query(User, "my-user-id")
          await scim.delete(user)

:doc:`how-to/version-resources-with-etags` covers the conditional headers a write carries when
the server supports them, which keep a modification from overwriting one made in between.

Send operations in bulk
-----------------------

:meth:`~scim2_client.BaseSyncSCIMClient.bulk` issues a ``POST`` on the ``/Bulk`` endpoint, which
carries several operations in one request and lets one of them refer to a resource another one
creates:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          from scim2_models import BulkOperation, BulkRequest, Group, GroupMember, User

          request = BulkRequest[User | Group](
              operations=[
                  BulkOperation[User](
                      method="POST",
                      path="/Users",
                      bulk_id="qwerty",
                      data=User(user_name="Alice"),
                  ),
                  BulkOperation[Group](
                      method="POST",
                      path="/Groups",
                      bulk_id="ytrewq",
                      data=Group(
                          display_name="Tour Guides",
                          members=[GroupMember(type="User", value="bulkId:qwerty")],
                      ),
                  ),
              ]
          )
          response = scim.bulk(request)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          from scim2_models import BulkOperation, BulkRequest, Group, GroupMember, User

          request = BulkRequest[User | Group](
              operations=[
                  BulkOperation[User](
                      method="POST",
                      path="/Users",
                      bulk_id="qwerty",
                      data=User(user_name="Alice"),
                  ),
                  BulkOperation[Group](
                      method="POST",
                      path="/Groups",
                      bulk_id="ytrewq",
                      data=Group(
                          display_name="Tour Guides",
                          members=[GroupMember(type="User", value="bulkId:qwerty")],
                      ),
                  ),
              ]
          )
          response = await scim.bulk(request)

:doc:`how-to/send-operations-in-bulk` covers reading the outcome of each operation, and the
limits a request is checked against before it is sent.

Read the errors a server returns
--------------------------------

A payload that does not comply, and an :class:`~scim2_models.Error` the server returned, both
raise. :meth:`~scim2_models.SCIMException.to_error`
gives the error object back:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          from scim2_models import SCIMException

          try:
              response = scim.create(request)
          except SCIMException as exc:
              error = exc.to_error()
              print(f"SCIM error [{error.status}] {error.scim_type}: {error.detail}")

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          from scim2_models import SCIMException

          try:
              response = await scim.create(request)
          except SCIMException as exc:
              error = exc.to_error()
              print(f"SCIM error [{error.status}] {error.scim_type}: {error.detail}")

:doc:`how-to/handle-errors` covers the exception hierarchy and what each family means.
:doc:`how-to/tolerate-a-nonconformant-peer` covers the checks an application may relax when the
server it talks to departs from the specification.
