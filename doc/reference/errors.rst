Errors
======

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
