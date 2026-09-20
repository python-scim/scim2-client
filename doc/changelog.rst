Changelog
=========

[Unreleased]
------------

Added
^^^^^
- The network request engines are built upon `httpx2 <https://github.com/pydantic/httpx2>`_,
  which is maintained, and live in ``scim2_client.engines.httpx2``.
  They are shipped in the ``httpx2`` packaging extra.
  `httpx <https://github.com/encode/httpx>`_ is still used when httpx2 is not installed.
- ``query``, ``delete`` and ``modify`` also accept a :class:`~scim2_models.Resource`
  object in place of a resource type and an id. Objects without an id are rejected.
  :issue:`13`
- ``replace``, ``modify`` and ``delete`` send an ``If-Match`` header when the server
  advertises ETag support and the resource they are given carries a version.
  :issue:`47`
- Resource versions are read from the ``ETag`` response header when the server does
  not fill the ``meta.version`` attribute. :issue:`47`
- ``409`` is an expected status code for ``delete``, as :rfc:`RFC7644 §3.12 <7644#section-3.12>`
  defines it for every write operation.

Changed
^^^^^^^
- scim2-models 0.8 is not supported yet, and 0.7.0 is now the minimum supported version.
- **Breaking:** invalid requests and server :class:`~scim2_models.Error` objects now raise
  :class:`~scim2_models.SCIMException` subclasses from scim2-models instead of scim2-client
  custom exceptions. :issue:`39`

Deprecated
^^^^^^^^^^
- The ``resource_model`` parameter of ``query``, ``delete`` and ``modify``, renamed
  ``target`` for ``query`` and ``resource`` for the two others, since it also accepts
  resource objects. Will be removed in 0.9.
- The ``httpx`` packaging extra, in favor of the ``httpx2`` extra. Will be removed in 0.9.
- The ``scim2_client.engines.httpx`` module, in favor of ``scim2_client.engines.httpx2``.
  Will be removed in 0.9.
- Passing a :code:`httpx.Client` or a :code:`httpx.AsyncClient` to the request engines,
  in favor of their httpx2 counterparts. Will be removed in 0.9.
- The exceptions with a ``*Error`` suffix, in favor of their ``*Exception`` counterparts.
  The old names still point at the renamed classes, so ``except`` blocks written against
  them keep working. Will be removed in 0.9.

Removed
^^^^^^^
- **Breaking:** ``SCIMRequestError``, ``RequestPayloadValidationError`` and
  ``SCIMResponseErrorObject``, which have no counterpart among the scim2-models exceptions.
  Code catching them must catch :class:`~scim2_models.SCIMException` instead, which is also
  what invalid request payloads and server errors now raise.

Fixed
^^^^^
- The ``create`` and ``query`` methods attach the server response to the exceptions they
  raise, as the other methods do, instead of the request payload.

[0.7.5] - 2026-04-02
--------------------

Fixed
^^^^^
- Werkzeug engine now correctly serializes list query parameters (``attributes``, ``excludedAttributes``).

[0.7.4] - 2026-04-02
--------------------

Changed
^^^^^^^
- The ``query`` method now accepts :class:`~scim2_models.ResponseParameters` in addition
  to :class:`~scim2_models.SearchRequest`.
- The ``search_request`` parameter of ``query`` is renamed to ``query_parameters``.
  The old name is deprecated and will be removed in 0.9.

[0.7.3] - 2026-02-04
--------------------

Changed
^^^^^^^
- ``SCIMResponseErrorObject`` now exposes a ``to_error()`` method
  returning the :class:`~scim2_models.Error` object from the server. :issue:`37`

[0.7.2] - 2026-02-03
--------------------

Fixed
^^^^^
- Skip ``Content-Type`` header validation for 204 responses. :issue:`34`

[0.7.1] - 2026-01-25
--------------------

Fixed
^^^^^
- ``schemas`` is no longer included in GET query parameters per RFC 7644 §3.4.2.

[0.7.0] - 2026-01-25
--------------------

Added
^^^^^
- Support for Python 3.14.
- Compatibility with scim2-models 0.6.

Removed
^^^^^^^
- Support for Python 3.9.

[0.6.1] - 2025-08-01
--------------------

Fixed
^^^^^
- Discovery for models with several extensions. :pr:`30` :pr:`32`


[0.6.0] - 2025-07-23
--------------------

Fixed
^^^^^
- Add support for PATCH operations with :meth:`~scim2_client.SCIMClient.modify`.

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
  ``UnexpectedContentFormat`` exception when response is not JSON.

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
- ``RequestPayloadValidationError`` error message.
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
- ``SCIMResponseErrorObject`` implementation.

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
- ``ResponsePayloadValidationError`` implementation.
- ``RequestPayloadValidationError`` implementation.
- ``RequestNetworkError`` implementation.

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
