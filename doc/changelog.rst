Changelog
=========

[0.5.2] - 2025-07-17
--------------------

Fixed
^^^^^
- Minor extension typing issue.

[0.5.1] - 2024-12-08
--------------------

Changed
^^^^^^^
- Check response return codes after the error state.
  This helps providing more useful error messages.

[0.5.0] - 2024-12-06
--------------------

.. warning::

    This version comes with breaking changes:

    - :class:`~scim2_client.engines.werkzeug.TestSCIMClient` ``app`` is dropped.

Added
^^^^^
- Add ``client`` and ``environ`` :class:`~scim2_client.engines.werkzeug.TestSCIMClient` parameters.

[0.4.3] - 2024-12-06
--------------------

Added
^^^^^
- Add :paramref:`~scim2_client.SCIMClient.check_response_content_type` and
  :paramref:`~scim2_client.SCIMClient.check_response_status_codes` parameters.

[0.4.2] - 2024-12-03
--------------------

Added
^^^^^
- :class:`~scim2_client.client.BaseSyncSCIMClient.discover` has parameters to select which objects to discover.

[0.4.1] - 2024-12-02
--------------------

Added
^^^^^
- :class:`~scim2_client.engines.werkzeug.TestSCIMClient` can handle absolute URLs.

Changed
^^^^^^^
- Avoid to initialize :paramref:`~scim2_client.SCIMClient.resource_models` with configuration resources.

[0.4.0] - 2024-12-02
--------------------

.. warning::

    This version comes with breaking changes:

    - :class:`~scim2_client.SCIMClient` takes a mandatory :paramref:`~scim2_client.SCIMClient.resource_types` parameter.

Added
^^^^^
- Implement :meth:`~scim2_client.SCIMClient.register_naive_resource_types`.
- Implement :meth:`~scim2_client.BaseSyncSCIMClient.discover` methods.

[0.3.3] - 2024-11-29
--------------------

Added
^^^^^
- :class:`~scim2_client.engines.werkzeug.TestSCIMClient` raise a
  :class:`~scim2_client.UnexpectedContentFormat` exception when response is not JSON.

[0.3.2] - 2024-11-29
--------------------

Added
^^^^^
- Implement :class:`~scim2_client.SCIMClient` :paramref:`~scim2_client.SCIMClient.check_request_payload`,
  :paramref:`~scim2_client.SCIMClient.check_response_payload` and
  :paramref:`~scim2_client.SCIMClient.raise_scim_errors` paramibutes,
  to keep the same values for all the requests.

[0.3.1] - 2024-11-29
--------------------

Fixed
^^^^^
- Some variables were missing from the SCIM exception classes.

[0.3.0] - 2024-11-29
--------------------

.. warning::

    This version comes with breaking changes:

    - `httpx` is no longer a direct dependency, it is shipped in the `httpx` packaging extra.
    - ``scim2_client.SCIMClient`` has moved to ``scim2_client.engines.httpx.SyncSCIMClient``.
    - The ``resource_types`` parameters has been renamed ``resource_models``.

Added
^^^^^
- The `Unknown resource type` request error keeps a reference to the faulty payload.
- New :class:`~scim2_client.engines.werkzeug.TestSCIMClient` request engine for application development purpose.
- New :class:`~scim2_client.engines.httpx.AsyncSCIMClient` request engine. :issue:`1`

Changed
^^^^^^^
- Separate httpx network code and SCIM code in separate file as a basis for async support (and other request engines).

[0.2.2] - 2024-11-12
--------------------

Added
^^^^^
- Mypy type checking and py.typed file :pr:`25`

[0.2.1] - 2024-11-07
--------------------

Added
^^^^^
- Python 3.13 support.

Fixed
^^^^^
- :class:`~scim2_client.RequestPayloadValidationError` error message.
- Don't crash when servers don't return content type headers. :pr:`22,24`

[0.2.0] - 2024-09-01
--------------------

Added
^^^^^
- Replace :code:`check_status_code` parameter by :code:`expected_status_codes`.

Changed
^^^^^^^
- :code:`raise_scim_errors` is :data:`True` by default.

[0.1.11] - 2024-08-31
---------------------

Fixed
^^^^^
- Support for content-types with charset information. :issue:`18,19`

[0.1.10] - 2024-08-18
---------------------

Changed
^^^^^^^
- Bump to scim2-models 0.2.0.

[0.1.9] - 2024-06-30
--------------------

Changed
^^^^^^^
- Fix httpx dependency versions.

[0.1.8] - 2024-06-30
--------------------

Changed
^^^^^^^
- Lower the httpx dependency to 0.24.0

[0.1.7] - 2024-06-28
--------------------

Fixed
^^^^^
- Support for scim2-models 0.1.8

[0.1.6] - 2024-06-05
--------------------

Added
^^^^^
- :class:`~scim2_client.SCIMResponseErrorObject` implementation.

[0.1.5] - 2024-06-05
--------------------

Changed
^^^^^^^
- Merge :meth:`~scim2_client.SCIMClient.query` and :meth:`~scim2_client.SCIMClient.query_all`.

Added
^^^^^
- Implement :meth:`~scim2_client.SCIMClient.delete` `check_response_payload` attribute.
- :class:`~scim2_models.ServiceProviderConfig`, :class:`~scim2_models.ResourceType`
  and :class:`~scim2_models.Schema` are added to the default resource types list.
- Any custom URL can be used with all the :class:`~scim2_client.SCIMClient` methods.
- :class:`~scim2_client.ResponsePayloadValidationError` implementation.
- :class:`~scim2_client.RequestPayloadValidationError` implementation.
- :class:`~scim2_client.RequestNetworkError` implementation.

Fixed
^^^^^
- Endpoint guessing for :class:`~scim2_models.ServiceProviderConfig`.
- :class:`~scim2_models.ServiceProviderConfig` cannot have ids and are not returned in :class:`~scim2_models.ListResponse`.

[0.1.4] - 2024-06-03
--------------------

Fixed
^^^^^
- :meth:`~scim2_client.SCIMClient.resource_endpoint` could not correctly guess endpoints for resources with extensions.

[0.1.3] - 2024-06-03
--------------------

Added
^^^^^
- :meth:`~scim2_client.SCIMClient.create` and :meth:`~scim2_client.SCIMClient.replace` can guess resource types by their payloads.

[0.1.2] - 2024-06-02
--------------------

Added
^^^^^
- :code:`check_response_payload` and :code:`check_status_code` parameters for all methods.
- :code:`check_request_payload` parameter for all methods.

[0.1.1] - 2024-06-01
--------------------

Added
^^^^^
- Use of scim2-models request contexts to produce adequate payloads.

[0.1.0] - 2024-06-01
--------------------

Added
^^^^^
- Initial release
