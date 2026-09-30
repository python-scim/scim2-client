What a client knows about a server
==================================

A SCIM client cannot build a request from a resource alone. It has to know which resources the
server serves, where it serves them, and what it is able to do. A
:class:`~scim2_models.ScimProvider` holds all three, and every request the client makes reads
one of them.

What a provider holds
---------------------

**Which models.** A payload arriving from the server is a JSON object whose ``schemas`` name
what it describes. The models the provider holds are what those names are matched against, so a
provider that does not know a schema cannot turn a payload into an object. The same list works
in the other direction: a resource an application asks to create, of a type the server does not
serve, is refused before a request is built.

**Which endpoints.** :rfc:`RFC7644 §4 <7644#section-4>` lets a server serve its resources
wherever it likes, and publish the mapping as :class:`~scim2_models.ResourceType` objects. The
client reads them to turn a model into a URL. It looks the model up first and the schema
second, so two resource types built upon a same schema — the same ``User`` schema served once
as ``/Users`` and once as ``/Employees``, for instance — are told apart instead of collapsing
into whichever came first.

**Which capabilities.** The :class:`~scim2_models.ServiceProviderConfig` says what the server
supports, and the client uses it instead of trying and failing. A server advertising ETag
support gets conditional headers on writes; a server advertising a cap on bulk operations gets
no request exceeding it. A client that never read the configuration sends no conditional
header, and sends bulk requests the server may refuse.

Why discovery only fills the gaps
---------------------------------

:meth:`~scim2_client.BaseSyncSCIMClient.discover` queries the three endpoints, but only those
the provider does not already describe. What an application passed by hand therefore survives
discovery.

Models built from the schemas a server publishes carry that server's attributes, which is what
an application wants when it does not know them in advance. An application that does know them
has usually written models of its own, with the Python types, the validators and the extensions
it cares about, and discovery replacing those with generated equivalents would be a loss.
Filling only the gaps lets it state the part it knows and ask the server for the rest, usually
the capabilities.

A description that does not hold together is refused as a whole, with
:exc:`~scim2_client.InvalidServiceDescriptionException`, instead of leaving the client with a
provider that describes some resource types and not others.
