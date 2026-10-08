Base client
===========

What every engine inherits: the description of the server it talks to, the preparation of the
requests, and the checking of the responses. The status codes each operation accepts are listed
here as class attributes.

.. autoclass:: scim2_client.SCIMClient
   :members:
   :member-order: bysource

.. autoclass:: scim2_client.BaseSyncSCIMClient
   :members:
   :member-order: bysource

.. autoclass:: scim2_client.BaseAsyncSCIMClient
   :members:
   :member-order: bysource

.. autodata:: scim2_client.Me
   :no-value:

.. autoclass:: scim2_client.client.ResponseHeaders
   :members:

.. autoclass:: scim2_client.client.RawResponse
   :members:
