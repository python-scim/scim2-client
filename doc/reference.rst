Reference
=========

This reference describes the public scim2-client API. It is generated from the API docstrings
and grouped by the kind of object it exposes. Use the :doc:`overview` and the
:doc:`how-to guides <how-to/index>` for procedures.

Engines
-------

The classes an application instantiates. Each one performs the requests with one HTTP library,
and inherits the payload handling from the base client.

.. autoclass:: scim2_client.engines.httpx2.SyncSCIMClient
   :members:
   :member-order: bysource

.. autoclass:: scim2_client.engines.httpx2.AsyncSCIMClient
   :members:
   :member-order: bysource

.. autoclass:: scim2_client.engines.werkzeug.TestSCIMClient
   :members:
   :member-order: bysource

Base client
-----------

What every engine inherits: the description of the server it talks to, the preparation of the
requests, and the checking of the responses. The status codes each operation accepts are listed
here as class attributes.

.. autoclass:: scim2_client.SCIMClient
   :members:
   :member-order: bysource

.. autoclass:: scim2_client.BaseSyncSCIMClient
   :members:
   :member-order: bysource

Errors
------

Exceptions raised when an exchange with a server cannot be completed. An
:class:`~scim2_models.Error` the server itself returned is raised as the matching
:class:`~scim2_models.SCIMException` subclass instead.

.. autoclass:: scim2_client.SCIMClientException
   :members:

.. autoclass:: scim2_client.RequestNetworkException
   :members:

.. autoclass:: scim2_client.SCIMResponseException
   :members:

.. autoclass:: scim2_client.UnexpectedStatusCodeException
   :members:

.. autoclass:: scim2_client.UnexpectedContentTypeException
   :members:

.. autoclass:: scim2_client.UnexpectedContentFormatException
   :members:

.. autoclass:: scim2_client.ResponsePayloadValidationException
   :members:

.. autoclass:: scim2_client.InvalidServiceDescriptionException
   :members:
