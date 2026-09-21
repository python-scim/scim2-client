Tutorial
--------

Initialization
==============

scim2-client depends on request engines such as `httpx2 <https://github.com/pydantic/httpx2>`_ to perform network requests.
This tutorial demonstrate how to use scim2-client with httpx2, and suppose you have installed the `httpx2` extra for example with ``pip install scim2-client[httpx2]``.

.. note::

   The engines still work with `httpx <https://github.com/encode/httpx>`_, shipped in the deprecated `httpx` extra.
   It is used when httpx2 is not installed, and both its extra and its support will be removed in 0.9.
   Applications that cannot migrate all their dependencies at once can call :code:`httpx2.alias_httpx()`
   at the very top of their entrypoint, so that :code:`import httpx` resolves to httpx2 process-wide.

As a start you will need to instantiate a httpx2 :code:`Client` (or :code:`AsyncClient`) object that you can parameter as your will, and then pass it to a :class:`~scim2_client.SCIMClient` object.
In addition to your SCIM server root endpoint, you will probably want to provide some authorization headers through the httpx2 :code:`Client` :code:`headers` parameter:

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

You need to indicate to :class:`~scim2_client.SCIMClient` which service it talks to: the :class:`~scim2_models.Resource` models that you will need to manipulate, the matching :class:`~scim2_models.ResourceType` objects that tell the client where to look for resources on the server, and the capabilities the server declares.
Those are gathered in a :class:`~scim2_models.ScimProvider`.

You can either provision it manually or automatically.

Automatic provisioning
~~~~~~~~~~~~~~~~~~~~~~

The easiest way is to let the client discover the server's configuration and available resources.
The :meth:`~scim2_client.BaseSyncSCIMClient.discover` method looks for the server :class:`~scim2_models.ServiceProviderConfig`, :class:`~scim2_models.Schema` and :class:`~scim2_models.ResourceType` endpoints,
and dynamically generate local Python models based on those schemas.
They are then available to use with :meth:`~scim2_client.SCIMClient.get_resource_model`.
Only what the :attr:`~scim2_client.SCIMClient.provider` does not describe yet is queried, so anything you pass by hand takes precedence over what the server publishes.

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python
          :caption: Dynamically discover models from the server

          scim.discover()
          User = scim.get_resource_model("User")
          EnterpriseUser = User.get_extension_model("EnterpriseUser")

   .. tab-item:: Async
      :sync: async

      .. code-block:: python
          :caption: Dynamically discover models from the server

          await scim.discover()
          User = scim.get_resource_model("User")
          EnterpriseUser = User.get_extension_model("EnterpriseUser")

Manual provisioning
~~~~~~~~~~~~~~~~~~~
To describe the server by hand, pass a :class:`~scim2_models.ScimProvider` with the :paramref:`~scim2_client.SCIMClient.provider` argument.
It lists the resources and the extensions apart, and binds them with the :class:`~scim2_models.ResourceType` objects the server serves them under.


.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python
          :caption: Manually describing the server

          from scim2_models import EnterpriseUser, Group, ResourceType, ScimProvider, User

          scim = SyncSCIMClient(
              client,
              provider=ScimProvider(
                  models=[User, EnterpriseUser, Group],
                  resource_types=[
                      ResourceType.from_resource(User[EnterpriseUser]),
                      ResourceType.from_resource(Group),
                  ],
              ),
          )

   .. tab-item:: Async
      :sync: async

      .. code-block:: python
          :caption: Manually describing the server

          from scim2_models import EnterpriseUser, Group, ResourceType, ScimProvider, User

          scim = AsyncSCIMClient(
              client,
              provider=ScimProvider(
                  models=[User, EnterpriseUser, Group],
                  resource_types=[
                      ResourceType.from_resource(User[EnterpriseUser]),
                      ResourceType.from_resource(Group),
                  ],
              ),
          )

.. tip::

   Resources that carry no extension and are hosted at regular server endpoints
   (for instance `/Users` for :class:`~scim2_models.User` etc.) need no
   :class:`~scim2_models.ResourceType`: the provider builds naive ones itself.

    .. tab-set::
       :class: outline

       .. tab-item:: Sync
          :sync: sync

          .. code-block:: python
              :caption: Describing a server serving bare resources

              from scim2_models import Group, ScimProvider, User

              scim = SyncSCIMClient(client, provider=ScimProvider(models=[User, Group]))

       .. tab-item:: Async
          :sync: async

          .. code-block:: python
              :caption: Describing a server serving bare resources

              from scim2_models import Group, ScimProvider, User

              scim = AsyncSCIMClient(client, provider=ScimProvider(models=[User, Group]))

Performing actions
==================

scim2-client allows your application to interact with a SCIM server as described in :rfc:`RFC7644 §3 <7644#section-3>`, so you can read and manage the resources.
Have a look at the :doc:`reference` to see the exhaustive set of parameters.

Create
~~~~~~

:meth:`~scim2_client.BaseSyncSCIMClient.create` issues a ``POST`` to provision a new resource:

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

Query
~~~~~

:meth:`~scim2_client.BaseSyncSCIMClient.query` issues a ``GET`` to read a single resource by its id, or list resources of a given type.

The resource to read is designated either by a resource type and an id, or by a
resource object carrying that id:

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

          response = await scim.query(User, query_parameters=SearchRequest(filter='userName sw "john"'))
          for user in response.resources:
              print(user.user_name)

Search
~~~~~~

:meth:`~scim2_client.BaseSyncSCIMClient.search` issues a ``POST`` on the ``/.search`` endpoint to query across all resource types at once:

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

Replace
~~~~~~~

:meth:`~scim2_client.BaseSyncSCIMClient.replace` issues a ``PUT`` to fully overwrite an existing resource:

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

Delete
~~~~~~

:meth:`~scim2_client.BaseSyncSCIMClient.delete` issues a ``DELETE`` and returns :data:`None` on success:

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

Modify
~~~~~~

:meth:`~scim2_client.BaseSyncSCIMClient.modify` issues a ``PATCH`` to apply partial updates as defined in :rfc:`RFC7644 §3.5.2 <7644#section-3.5.2>`:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          from scim2_models import PatchOp, PatchOperation

          patch = PatchOp[User](operations=[
              PatchOperation(op=PatchOperation.Op.replace_, path="displayName", value="New Name"),
              PatchOperation(op=PatchOperation.Op.add, path="emails", value=[{"value": "new@example.com"}]),
          ])
          user = scim.query(User, "my-user-id")
          response = scim.modify(user, patch)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          from scim2_models import PatchOp, PatchOperation

          patch = PatchOp[User](operations=[
              PatchOperation(op=PatchOperation.Op.replace_, path="displayName", value="New Name"),
              PatchOperation(op=PatchOperation.Op.add, path="emails", value=[{"value": "new@example.com"}]),
          ])
          user = await scim.query(User, "my-user-id")
          response = await scim.modify(user, patch)

Bulk
~~~~

:meth:`~scim2_client.BaseSyncSCIMClient.bulk` issues a ``POST`` on the ``/Bulk`` endpoint to execute multiple operations at once:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          from scim2_models import BulkRequest, BulkOperation, Group, GroupMember, User

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

          from scim2_models import BulkRequest, BulkOperation, Group, GroupMember, User

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

A bulk job the server processed answers ``200``, whatever the outcome of the operations
it carried. Failed operations raise nothing, and each of them carries its own ``status``
and an :class:`~scim2_models.Error` object in its ``response`` attribute:

.. code-block:: python

    for operation in response.operations:
        if operation.status >= 400:
            print(operation.bulk_id, operation.response.detail)

When the :class:`~scim2_models.ServiceProviderConfig` is known — after a call to
:meth:`~scim2_client.BaseSyncSCIMClient.discover` for instance — bulk requests are
checked against the capabilities the server advertises. Requests aimed at a server
that does not support bulk operations, and requests exceeding its ``maxOperations``
or ``maxPayloadSize`` limits, are not sent.

Error handling
==============

By default, if the request payload is invalid or if the server returns an error,
a :class:`~scim2_models.SCIMException` exception is raised.
The :meth:`~scim2_models.SCIMException.to_error` method gives access to the :class:`~scim2_models.Error` object:

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

Exceptions raised while validating the request payload happen before anything is
sent. They keep the original :class:`ValidationError <pydantic_core.ValidationError>`, which lists every
invalid attribute, in :attr:`~BaseException.__cause__`.

Request and response validation
===============================

By default, scim2-client validates both request payloads and server responses against the SCIM specifications, raising an error on non-compliance.
However sometimes you want to accept invalid inputs and outputs.
To achieve this, all the methods provide the following parameters, all are :data:`True` by default:

- :paramref:`~scim2_client.SCIMClient.check_request_payload`:
  If :data:`True` (the default) a :class:`~scim2_models.SCIMException` will be raised if the input does not respect the SCIM standard.
  If :data:`False`, input is expected to be a :class:`dict` that will be passed as-is in the request.
- :paramref:`~scim2_client.SCIMClient.check_response_payload`:
  If :data:`True` (the default) a :class:`~scim2_client.ResponsePayloadValidationException` will be raised if the server response does not respect the SCIM standard.
  If :data:`False` the server response is returned as-is.
- :code:`expected_status_codes`: The list of expected status codes in the response.
  If :data:`None` any status code is accepted.
  If an unexpected status code is returned, a :class:`~scim2_client.errors.UnexpectedStatusCodeException` exception is raised.
- :paramref:`~scim2_client.SCIMClient.raise_scim_errors`: If :data:`True` (the default) and the server returned an :class:`~scim2_models.Error` object, a :class:`~scim2_models.SCIMException` exception will be raised.
  The :meth:`~scim2_models.SCIMException.to_error` method gives access to the :class:`~scim2_models.Error` object.
  If :data:`False` the error object is returned directly.


.. tip::

   Check the request :class:`Contexts <scim2_models.Context>` to understand
   which value will excluded from the request payload, and which values are
   expected in the response payload.

Resource versioning (ETags)
===========================

SCIM supports resource versioning through HTTP ETags
(:rfc:`RFC7644 §3.14 <7644#section-3.14>`).
When the server advertises ETag support in its
:class:`~scim2_models.ServiceProviderConfig`, scim2-client automatically makes
write operations conditional: :meth:`~scim2_client.BaseSyncSCIMClient.replace`,
:meth:`~scim2_client.BaseSyncSCIMClient.modify` and
:meth:`~scim2_client.BaseSyncSCIMClient.delete` send an ``If-Match`` header
built from the :attr:`meta.version <scim2_models.Meta.version>` of the resource
they are given.

This implements optimistic concurrency control: the server rejects the request
with a ``412 Precondition Failed`` error if the resource has been modified since
it was read.

.. note::

   The client only knows about ETag support once it has read the
   :class:`~scim2_models.ServiceProviderConfig`, either with
   :meth:`~scim2_client.BaseSyncSCIMClient.discover` or by passing it to the
   client :paramref:`~scim2_client.SCIMClient.service_provider_config`
   parameter.

Conditional headers are only sent for resources the client has actually read,
since it is the server that fills the version. They are read from the
``ETag`` response header, or from the
:attr:`meta.version <scim2_models.Meta.version>` attribute when the server
fills it.

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          from scim2_models import SCIMException

          scim.discover()

          # The version is read from the server response
          user = scim.query(User, "my-user-id")

          # If-Match is sent automatically
          user.display_name = "Updated Name"
          try:
              user = scim.replace(user)
          except SCIMException as exc:
              if exc.status == 412:
                  print("The resource has changed, read it again")
              else:
                  raise

          # If-Match is sent automatically here too
          scim.delete(user)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          from scim2_models import SCIMException

          await scim.discover()

          # The version is read from the server response
          user = await scim.query(User, "my-user-id")

          # If-Match is sent automatically
          user.display_name = "Updated Name"
          try:
              user = await scim.replace(user)
          except SCIMException as exc:
              if exc.status == 412:
                  print("The resource has changed, read it again")
              else:
                  raise

          # If-Match is sent automatically here too
          await scim.delete(user)

Reads are conditional too: :meth:`~scim2_client.BaseSyncSCIMClient.query` sends
an ``If-None-Match`` header when it is given a versioned resource object. When
the server answers with a ``304 Not Modified``, nothing is downloaded and the
object that was passed is returned back:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          user = scim.query(User, "my-user-id")

          # If-None-Match is sent; 'fresh' is 'user' itself on a 304
          fresh = scim.query(user)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          user = await scim.query(User, "my-user-id")

          # If-None-Match is sent; 'fresh' is 'user' itself on a 304
          fresh = await scim.query(user)

.. warning::

   On a ``304 Not Modified`` the very object that was passed is returned, not a
   copy. Local modifications made to it are therefore given back as if they came
   from the server.

No ``If-None-Match`` is sent when ``query_parameters`` are used, since the server
would then answer with a partial representation that the cached object cannot
stand for.

No additional configuration is needed. When the server does not advertise ETag
support, or when the resource carries no version, no conditional header is sent.

Engines
=======

scim2-client comes with a light abstraction layers that allows for different requests engines.
Currently those engines are shipped:

- :class:`~scim2_client.engines.httpx2.SyncSCIMClient`: A synchronous engine using `httpx2 <https://github.com/pydantic/httpx2>`_ to perform the HTTP requests.
- :class:`~scim2_client.engines.httpx2.AsyncSCIMClient`: An asynchronous engine using `httpx2 <https://github.com/pydantic/httpx2>`_ to perform the HTTP requests. It has the very same API than its synchronous version, except it is asynchronous.
- :class:`~scim2_client.engines.werkzeug.TestSCIMClient`: A test engine for development purposes.
  It takes a WSGI app and directly execute the server code instead of performing real HTTP requests.
  This is faster in unit test suites, and helpful to catch the server exceptions.

You can easily implement your own engine by inheriting from :class:`~scim2_client.SCIMClient`.

Additional request parameters
=============================

Pass additional parameters directly to the underlying engine methods.
This can be useful if you need to explicitly pass a certain URL for example:

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
