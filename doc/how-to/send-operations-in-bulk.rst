Send operations in bulk
=======================

Use this guide to carry several modifications in one request, as
:rfc:`RFC7644 §3.7 <7644#section-3.7>` defines them. A bulk request suits a provisioning run
creating many resources at once, and it is the only way to create a resource that refers to
another one created in the same exchange.

Build the request
-----------------

:meth:`~scim2_client.BaseSyncSCIMClient.bulk` takes a :class:`~scim2_models.BulkRequest`
parameterized on the resource types its operations carry. Each
:class:`~scim2_models.BulkOperation` names a method, a path and the data it sends:

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

The ``bulk_id`` of an operation names the resource it creates, and another operation refers to
it with ``bulkId:`` followed by that name. The server resolves the reference into the identifier
it assigned, so the group above is created with the user above as a member without a round trip
in between.

Read the outcome of each operation
----------------------------------

A bulk job the server processed returns ``200``, whatever the outcome of the operations it
carried. A failed operation raises nothing: each one carries its own ``status`` and, when it
failed, an :class:`~scim2_models.Error` object in its ``response`` attribute:

.. code-block:: python

    for operation in response.operations:
        if operation.status >= 400:
            print(operation.bulk_id, operation.response.detail)


Stay within the limits the server advertises
--------------------------------------------

:rfc:`RFC7644 §3.7.4 <7644#section-3.7.4>` lets a server cap the number of operations and the
size of the payload it accepts, and declare both in its
:class:`~scim2_models.ServiceProviderConfig`. Once that configuration is known — after a call to
:meth:`~scim2_client.BaseSyncSCIMClient.discover`, or because it was passed to the client — a
request exceeding either cap is refused locally, and a request aimed at a server declaring it
serves no bulk endpoint is not sent at all:

.. code-block:: python

    from scim2_models import InvalidValueException

    scim.discover()
    try:
        response = scim.bulk(request)
    except InvalidValueException as exc:
        print(f"The request was not sent: {exc.detail}")

When the configuration is unknown, the request is sent as written.
