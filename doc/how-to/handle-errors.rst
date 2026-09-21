Handle errors
=============

Use this guide to tell apart the ways a request can fail, and to decide which ones an
application catches. Two families of exception say two different things: whether the exchange
happened at all, and whether the server accepted what it carried.

Catch the error a server returns
--------------------------------

A server refusing a request returns an :class:`~scim2_models.Error` object, which scim2-client
raises as the matching :class:`~scim2_models.SCIMException` subclass.
:meth:`~scim2_models.SCIMException.to_error` gives the object back:

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

An application preferring a value to an exception passes
:paramref:`~scim2_client.SCIMClient.raise_scim_errors` as :data:`False`, on the client or on one
call, and reads the :class:`~scim2_models.Error` among the return values:

.. code-block:: python

    from scim2_models import Error

    response = scim.create(request, raise_scim_errors=False)
    if isinstance(response, Error):
        print(response.detail)

Catch the errors of the exchange itself
---------------------------------------

Everything scim2-client raises on its own derives from :exc:`~scim2_client.SCIMClientException`,
and says at which point the exchange stopped:

:exc:`~scim2_client.RequestNetworkException`
    The engine could not reach the server. The original error is in
    :attr:`~BaseException.__cause__`.

:exc:`~scim2_client.UnexpectedStatusCodeException`
    The server answered a status code the operation does not define, listed per operation in
    the class attributes of :class:`~scim2_client.SCIMClient`.

:exc:`~scim2_client.UnexpectedContentTypeException`
    The response carried neither ``application/scim+json`` nor ``application/json``.

:exc:`~scim2_client.UnexpectedContentFormatException`
    The response body was not JSON.

:exc:`~scim2_client.ResponsePayloadValidationException`
    The body was JSON, but not a payload the expected model accepts. The
    :class:`ValidationError <pydantic_core.ValidationError>` listing every invalid attribute is
    in :attr:`~BaseException.__cause__`.

:exc:`~scim2_client.InvalidServiceDescriptionException`
    The objects the server publishes do not describe a service that holds together. Raised by
    :meth:`~scim2_client.BaseSyncSCIMClient.discover`.

Every one but the first shares :exc:`~scim2_client.SCIMResponseException`, which catches any
fault of a response in one clause:

.. code-block:: python

    from scim2_client import SCIMResponseException

    try:
        user = scim.query(User, "my-user-id")
    except SCIMResponseException as exc:
        print(f"The server answered something unusable: {exc}")

Read the cause of a request the client refused
----------------------------------------------

A :class:`dict` payload that does not comply is refused before anything is sent, so no request
reaches the server. The :class:`~scim2_models.SCIMException` raised keeps the
:class:`ValidationError <pydantic_core.ValidationError>` listing every invalid attribute in
:attr:`~BaseException.__cause__`:

.. code-block:: python

    from scim2_models import SCIMException

    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": None,
    }
    try:
        scim.create(payload)
    except SCIMException as exc:
        for detail in exc.__cause__.errors():
            print(detail["loc"], detail["msg"])

:doc:`tolerate-a-nonconformant-peer` covers sending such a payload anyway, for a server whose
expectations differ from the specifications.
