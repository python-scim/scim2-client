Version resources with ETags
============================

Use this guide to keep a modification from overwriting one made in between, and to skip a
download that would bring back a resource unchanged. Both rest on the HTTP entity tags
:rfc:`RFC7644 §3.14 <7644#section-3.14>` binds to the
:attr:`meta.version <scim2_models.Meta.version>` attribute of a resource.

Nothing has to be configured. A client that has read the
:class:`~scim2_models.ServiceProviderConfig` of a server advertising ETag support sends the
conditional headers on its own, and sends none when the server does not advertise it or when
the resource at hand carries no version.

.. note::

   The client only learns of that support once it has read the
   :class:`~scim2_models.ServiceProviderConfig`, either with
   :meth:`~scim2_client.BaseSyncSCIMClient.discover` or by passing it in the
   :paramref:`~scim2_client.SCIMClient.provider` describing the server.

Refuse a write that would overwrite a change
--------------------------------------------

:meth:`~scim2_client.BaseSyncSCIMClient.replace`,
:meth:`~scim2_client.BaseSyncSCIMClient.modify` and
:meth:`~scim2_client.BaseSyncSCIMClient.delete` send an ``If-Match`` header built from the
version of the resource they are given. The server returns ``412 Precondition Failed`` when the
resource changed since it was read, which is the optimistic concurrency control the
specification describes:

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

The version is read from the ``ETag`` response header, or from the
:attr:`meta.version <scim2_models.Meta.version>` attribute when the server fills it. A write
aimed at a resource the client never read carries no header, since it is the server that
assigns the version.

Skip a download that would change nothing
-----------------------------------------

Reads are conditional too. :meth:`~scim2_client.BaseSyncSCIMClient.query` sends an
``If-None-Match`` header when it is given a versioned resource object. The server returns
``304 Not Modified`` when the resource did not change, nothing is downloaded, and the object
that was passed is returned:

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

   On a ``304 Not Modified`` the very object that was passed is returned, not a copy. Local
   modifications made to it are therefore given back as if they came from the server.

No ``If-None-Match`` is sent when ``query_parameters`` are used, since the server would then
answer a partial representation that the cached object cannot stand for.
