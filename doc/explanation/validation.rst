What the client checks
======================

scim2-client checks the payloads it sends as closely as the ones it receives. A client checking
what it wrote may look redundant, since the server is going to check it again. They are not the
same check, and the local one does more than refuse.

Why a client checks its own requests
------------------------------------

A payload refused locally never leaves the process. The exception names the attribute at fault
and carries the whole :class:`ValidationError <pydantic_core.ValidationError>`, where the
server would have returned a ``400`` whose ``detail`` is one sentence written by its author.

The check also shapes the payload, which is the part a server cannot do for the client. Each
operation is validated and serialized under the :class:`~scim2_models.Context` matching it, and
a context drops the attributes that operation has no business sending: the ``id`` an
application filled on a resource it is about to create is left out of the ``POST``, because
:rfc:`RFC7643 §7 <7643#section-7>` makes it read-only and the server assigns it. Turning the
check off with :paramref:`~scim2_client.SCIMClient.check_request_payload` therefore turns the
filtering off too, and the payload is sent exactly as it was given.

What a response is checked against
----------------------------------

A response is checked in four passes.

The ``Content-Type`` comes first, since a body that is not SCIM JSON cannot be read as one.
:rfc:`RFC7644 §8.1 <7644#section-8.1>` names ``application/scim+json``, and
``application/json`` is accepted alongside it because older implementations use it.

The body is then read as an :class:`~scim2_models.Error` when its ``schemas`` say so. This
happens **before** the status code is examined, so a server returning a well-formed SCIM error
under a status code the operation does not define raises that error, not
:exc:`~scim2_client.UnexpectedStatusCodeException`.

The status code is checked next, against the list the operation defines — the class attributes
of :class:`~scim2_client.SCIMClient` hold them, each one sourced from the section of
:rfc:`RFC7644 <7644>` that defines the operation.

The payload is validated last, under the response context of the operation, and against the
resource types that operation could return. A payload whose ``schemas`` match none of them
raises before any attribute is read: validated against a model it does not describe, it would
report faults that are not there.

Why the default is to refuse
----------------------------

scim2-models refuses anything the specifications do not describe unless it is given a
:class:`~scim2_models.ScimPolicy` saying otherwise, and scim2-client neither widens nor narrows
that. Its reasons, and the consequence that a client reads a response as strictly as a server
reads a request, are set out in
:doc:`its own explanation <scim2_models:explanation/policies>`.

The application is left with a choice at two grains. A check covers a whole payload and is turned
off on the client or on one call. A policy states one departure and leaves the rest of the
validation standing; it travels with the :class:`~scim2_models.ScimProvider` describing the server,
so it applies to the payloads the client reads and to the ones it writes.
:doc:`../how-to/tolerate-a-nonconformant-peer` shows both.
