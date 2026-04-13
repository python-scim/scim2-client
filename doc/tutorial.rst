Tutorial
--------

Initialization
==============

scim2-client depends on request engines such as `httpx <https://github.com/encode/httpx>`_ to perform network requests.
This tutorial demonstrate how to use scim2-client with httpx, and suppose you have installed the `httpx` extra for example with ``pip install scim2-client[httpx]``.

As a start you will need to instantiate a httpx :code:`Client` (or :code:`AsyncClient`) object that you can parameter as your will, and then pass it to a :class:`~scim2_client.SCIMClient` object.
In addition to your SCIM server root endpoint, you will probably want to provide some authorization headers through the httpx :code:`Client` :code:`headers` parameter:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          from httpx import Client
          from scim2_client.engines.httpx import SyncSCIMClient

          client = Client(
              base_url="https://auth.example/scim/v2",
              headers={"Authorization": "Bearer foobar"},
          )
          scim = SyncSCIMClient(client)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          from httpx import AsyncClient
          from scim2_client.engines.httpx import AsyncSCIMClient

          client = AsyncClient(
              base_url="https://auth.example/scim/v2",
              headers={"Authorization": "Bearer foobar"},
          )
          scim = AsyncSCIMClient(client)

You need to give to indicate to :class:`~scim2_client.SCIMClient` all the different :class:`~scim2_models.Resource` models that you will need to manipulate, and the matching :class:`~scim2_models.ResourceType` objects to let the client know where to look for resources on the server.

You can either provision those objects manually or automatically.

Automatic provisioning
~~~~~~~~~~~~~~~~~~~~~~

The easiest way is to let the client discover the server's configuration and available resources.
The :meth:`~scim2_client.BaseSyncSCIMClient.discover` method looks for the server :class:`~scim2_models.ServiceProviderConfig`, :class:`~scim2_models.Schema` and :class:`~scim2_models.ResourceType` endpoints,
and dynamically generate local Python models based on those schemas.
They are then available to use with :meth:`~scim2_client.SCIMClient.get_resource_model`.

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
To manually register models and resource types, you can simply use the :paramref:`~scim2_client.SCIMClient.resource_models` and :paramref:`~scim2_client.SCIMClient.resource_types` arguments.


.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python
          :caption: Manually registering models and resource types

          from scim2_models import User, EnterpriseUserUser, Group, ResourceType
          scim = SyncSCIMClient(
              client,
              resource_models=[User[EnterpriseUser], Group],
              resource_types=[ResourceType(id="User", ...), ResourceType(id="Group", ...)],
          )

   .. tab-item:: Async
      :sync: async

      .. code-block:: python
          :caption: Manually registering models and resource types

          from scim2_models import User, EnterpriseUserUser, Group, ResourceType
          scim = AsyncSCIMClient(
              client,
              resource_models=[User[EnterpriseUser], Group],
              resource_types=[ResourceType(id="User", ...), ResourceType(id="Group", ...)],
          )

.. tip::

   If you know that all the resources are hosted at regular server endpoints
   (for instance `/Users` for :class:`~scim2_models.User` etc.),
   you can skip passing the :class:`~scim2_models.ResourceType` objects by hand,
   and simply call :meth:`~scim2_client.SCIMClient.register_naive_resource_types`.

    .. tab-set::
       :class: outline

       .. tab-item:: Sync
          :sync: sync

          .. code-block:: python
              :caption: Manually registering models and resource types

              from scim2_models import User, EnterpriseUserUser, Group, ResourceType
              scim = SyncSCIMClient(
                  client,
                  resource_models=[User[EnterpriseUser], Group],
              )
              scim.register_naive_resource_types()

       .. tab-item:: Async
          :sync: async

          .. code-block:: python
              :caption: Manually registering models and resource types

              from scim2_models import User, EnterpriseUserUser, Group, ResourceType
              scim = AsyncSCIMClient(
                  client,
                  resource_models=[User[EnterpriseUser], Group],
              )
              scim.register_naive_resource_types()

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

:meth:`~scim2_client.BaseSyncSCIMClient.query` issues a ``GET`` to read a single resource by its id, or list resources of a given type:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          from scim2_models import SearchRequest

          user = scim.query(User, "my-user-id")

          response = scim.query(User, query_parameters=SearchRequest(filter='userName sw "john"'))
          for user in response.resources:
              print(user.user_name)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          from scim2_models import SearchRequest

          user = await scim.query(User, "my-user-id")

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

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          await scim.delete(User, "my-user-id")

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
          response = scim.modify(User, "my-user-id", patch)

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          from scim2_models import PatchOp, PatchOperation

          patch = PatchOp[User](operations=[
              PatchOperation(op=PatchOperation.Op.replace_, path="displayName", value="New Name"),
              PatchOperation(op=PatchOperation.Op.add, path="emails", value=[{"value": "new@example.com"}]),
          ])
          response = await scim.modify(User, "my-user-id", patch)

Bulk
~~~~

.. note::

    Bulk operation requests are not yet implemented,
    but :doc:`any help is welcome! <contributing>`

Error handling
==============

By default, if the server returns an error, a :class:`~scim2_client.SCIMResponseErrorObject` exception is raised.
The :meth:`~scim2_client.SCIMResponseErrorObject.to_error` method gives access to the :class:`~scim2_models.Error` object:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          from scim2_client import SCIMResponseErrorObject

          try:
              response = scim.create(request)
          except SCIMResponseErrorObject as exc:
              error = exc.to_error()
              print(f"SCIM error [{error.status}] {error.scim_type}: {error.detail}")

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          from scim2_client import SCIMResponseErrorObject

          try:
              response = await scim.create(request)
          except SCIMResponseErrorObject as exc:
              error = exc.to_error()
              print(f"SCIM error [{error.status}] {error.scim_type}: {error.detail}")

Request and response validation
===============================

By default, scim2-client validates both request payloads and server responses against the SCIM specifications, raising an error on non-compliance.
However sometimes you want to accept invalid inputs and outputs.
To achieve this, all the methods provide the following parameters, all are :data:`True` by default:

- :paramref:`~scim2_client.SCIMClient.check_request_payload`:
  If :data:`True` (the default) a :class:`~pydantic.ValidationError` will be raised if the input does not respect the SCIM standard.
  If :data:`False`, input is expected to be a :data:`dict` that will be passed as-is in the request.
- :paramref:`~scim2_client.SCIMClient.check_response_payload`:
  If :data:`True` (the default) a :class:`~pydantic.ValidationError` will be raised if the server response does not respect the SCIM standard.
  If :data:`False` the server response is returned as-is.
- :code:`expected_status_codes`: The list of expected status codes in the response.
  If :data:`None` any status code is accepted.
  If an unexpected status code is returned, a :class:`~scim2_client.errors.UnexpectedStatusCode` exception is raised.
- :paramref:`~scim2_client.SCIMClient.raise_scim_errors`: If :data:`True` (the default) and the server returned an :class:`~scim2_models.Error` object, a :class:`~scim2_client.SCIMResponseErrorObject` exception will be raised.
  The :meth:`~scim2_client.SCIMResponseErrorObject.to_error` method gives access to the :class:`~scim2_models.Error` object.
  If :data:`False` the error object is returned directly.


.. tip::

   Check the request :class:`Contexts <scim2_models.Context>` to understand
   which value will excluded from the request payload, and which values are
   expected in the response payload.

Engines
=======

scim2-client comes with a light abstraction layers that allows for different requests engines.
Currently those engines are shipped:

- :class:`~scim2_client.engines.httpx.SyncSCIMClient`: A synchronous engine using `httpx <https://github.com/encode/httpx>`_ to perform the HTTP requests.
- :class:`~scim2_client.engines.httpx.AsyncSCIMClient`: An asynchronous engine using `httpx <https://github.com/encode/httpx>`_ to perform the HTTP requests. It has the very same API than its synchronous version, except it is asynchronous.
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
