Engines
=======

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
