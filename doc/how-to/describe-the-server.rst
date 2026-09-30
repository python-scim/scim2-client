Describe the server
===================

Use this guide to tell a client which resources a server serves, under which endpoints, and what
it is capable of. A :class:`~scim2_models.ScimProvider` holds the three, and the client reads it
to pick the model a payload deserves and the URL a request goes to. See
:doc:`../explanation/service-description` for what the client does with each part.

Let the server publish it
-------------------------

:meth:`~scim2_client.BaseSyncSCIMClient.discover` reads the
:class:`~scim2_models.ServiceProviderConfig`, :class:`~scim2_models.Schema` and
:class:`~scim2_models.ResourceType` endpoints :rfc:`RFC7644 §4 <7644#section-4>` defines, and
builds a model for every schema it finds:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          scim.discover()
          User = scim.get_resource_model("User")
          EnterpriseUser = User.get_extension_model("EnterpriseUser")

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          await scim.discover()
          User = scim.get_resource_model("User")
          EnterpriseUser = User.get_extension_model("EnterpriseUser")

:meth:`~scim2_client.SCIMClient.get_resource_model` returns the model a resource type is served
under, and :data:`None` for a name the server does not serve. The models discovery builds carry
the attributes that server declares, extensions included, not the ones the specifications
describe.

Each of the three endpoints can be left out, for a server that does not serve it:

.. code-block:: python

    scim.discover(service_provider_config=False)

Describe it by hand
-------------------

A server whose resources are known in advance needs no round trip. Pass a
:class:`~scim2_models.ScimProvider` as the :paramref:`~scim2_client.SCIMClient.provider`
argument, listing the models and the :class:`~scim2_models.ResourceType` objects binding them to
their endpoints:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

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

Resources carrying no extension and served at the regular endpoints — ``/Users`` for
:class:`~scim2_models.User`, and so on — need no :class:`~scim2_models.ResourceType` at all, as
the provider builds those itself:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          from scim2_models import Group, ScimProvider, User

          scim = SyncSCIMClient(client, provider=ScimProvider(models=[User, Group]))

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          from scim2_models import Group, ScimProvider, User

          scim = AsyncSCIMClient(client, provider=ScimProvider(models=[User, Group]))

Describe what is known and discover the rest
--------------------------------------------

:meth:`~scim2_client.BaseSyncSCIMClient.discover` only queries what the
:attr:`~scim2_client.SCIMClient.provider` does not describe yet, so a client given part of the
description keeps it and asks the server for the remainder. A server whose models are known but
whose capabilities are not reads the latter alone:

.. code-block:: python

    scim = SyncSCIMClient(client, provider=ScimProvider(models=[User, Group]))

    # Only the ServiceProviderConfig endpoint is queried
    scim.discover()

A server publishing a description that does not hold together — a resource type naming a schema
it does not publish, for instance — raises
:exc:`~scim2_client.InvalidServiceDescriptionException`, and the client keeps the description
it had.
