Tolerate a non-conformant peer
==============================

Use this guide when a server sends payloads scim2-client refuses, or expects payloads it
refuses to build. Two levers do that, at different grains: a check can be turned off for a
whole payload, or a :class:`~scim2_models.ScimPolicy` can state how far a payload may depart
from the specifications. See :doc:`../explanation/validation` for what the client checks in the
first place.

Turn a check off
----------------

Each check covers a whole payload, and each one is set on the client and overridden on a call:

:paramref:`~scim2_client.SCIMClient.check_request_payload`
    :data:`False` expects a :class:`dict`, and sends it as it is. Nothing is validated, and no
    attribute is filtered out by the context of the operation.

:paramref:`~scim2_client.SCIMClient.check_response_payload`
    :data:`False` returns the payload of the response as a :class:`dict`, without building a
    model from it.

:paramref:`~scim2_client.SCIMClient.raise_scim_errors`
    :data:`False` returns the :class:`~scim2_models.Error` a server answered instead of raising
    it.

``expected_status_codes``
    The codes the operation accepts, :data:`None` for any. A code outside the list raises
    :exc:`~scim2_client.UnexpectedStatusCodeException`.

.. code-block:: python

    # For every request this client makes
    scim = SyncSCIMClient(client, check_response_payload=False)

    # For this one only
    payload = scim.query(User, "my-user-id", check_response_payload=False)

Two more are set on the client alone, for a server whose HTTP layer is at fault and not its
payloads:

:paramref:`~scim2_client.SCIMClient.check_response_content_type`
    :data:`False` accepts a response whose ``Content-Type`` is neither
    ``application/scim+json`` nor ``application/json``.

:paramref:`~scim2_client.SCIMClient.check_response_status_codes`
    :data:`False` accepts any status code, whatever ``expected_status_codes`` says.

.. tip::

   Check the request :class:`Contexts <scim2_models.Context>` to understand which values are
   excluded from a request payload, and which ones are expected in a response payload.

State how far a payload may depart
----------------------------------

Turning a check off gives up on a whole payload. When a server departs from the specifications
on one point only, a :class:`~scim2_models.ScimPolicy` states which departure to accept, and
everything else stays validated. The policy travels with the
:class:`~scim2_models.ScimProvider` describing the server:

.. tab-set::
   :class: outline

   .. tab-item:: Sync
      :sync: sync

      .. code-block:: python

          from scim2_models import ScimPolicy, ScimProvider, User

          scim = SyncSCIMClient(
              client,
              provider=ScimProvider(
                  models=[User],
                  policy=ScimPolicy(unknown=ScimPolicy.Unknown.keep),
              ),
          )

   .. tab-item:: Async
      :sync: async

      .. code-block:: python

          from scim2_models import ScimPolicy, ScimProvider, User

          scim = AsyncSCIMClient(
              client,
              provider=ScimProvider(
                  models=[User],
                  policy=ScimPolicy(unknown=ScimPolicy.Unknown.keep),
              ),
          )

Under ``Unknown.keep``, an attribute no schema declares is read instead of refused, and written
back to the server it came from:

.. code-block:: python

    user = scim.query(User, "my-user-id")
    user.unknown_attributes["acmeDepartment"]

The client applies the policy to every payload it reads and it writes, so one provider covers
both directions. ``Unknown.ignore`` reads the same payloads without sending those attributes
back.

The policy belongs to scim2-models, and
:doc:`its guide <scim2_models:how-to/tolerate-a-nonconformant-peer>` lists every departure one
can state — among them the ``remove`` operation carrying its target in ``value``, which
Microsoft Entra ID sends.
