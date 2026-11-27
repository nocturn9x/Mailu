.. _mailu_restful_api:

Mailu RESTful API
=================

Mailu offers a RESTful API for changing the Mailu configuration.
Anything that can be configured via the Mailu web administration interface,
can also be configured via the API.

The Mailu API can be configured via the setup utility (setup.mailu.io).
It can also be manually configured via mailu.env:

* ``API`` - Expose the API interface (value: true, false)
* ``API_TOKEN`` - API token for authentication (with minimum length of 3 characters)

The API interface is available at ``/api``.

For more information refer to the detailed descriptions in the
:ref:`configuration reference <advanced_settings>`.


Swagger.json
------------

The swagger.json file can be retrieved via: https://myserver/api/v1/swagger.json

The swagger.json file can be consumed in programs such as Postman for generating all API calls.

Passkey policy and account setup
--------------------------------

The versioned API exposes ``passkey_require_enrollment`` on domain create,
read, and update operations. User create, read, and update operations expose
``passkey_enroll_next_login``. These fields use the same policy as the
corresponding domain and user administration forms. ``raw_password`` is
optional when creating a user, so an account can be created for setup through
a one-time link without first assigning a password.

To generate or replace a one-time account setup or recovery link, send an
authenticated ``POST`` request to ``/api/v1/user/{email}/setup-link``. The
response contains the URL and its UTC expiration time. Generating a replacement
invalidates any previous link for that user. The link can set a password or add
a passkey according to the account's policy and the configured
``ACCOUNT_SETUP_TOKEN_TTL``.


In-built SwaggerUI
------------------
The Mailu API comes with an in-built SwaggerUI. It is a web client that allows
anyone to visualize and interact with the Mailu API.

The API is accessible via the URL: https://myserver/api/


SCIM 2.0 User Provisioning
--------------------------

Mailu exposes a Users-only SCIM 2.0 (RFC 7643 / RFC 7644) provisioning API under
``/api/scim/v2`` whenever ``API=true`` and ``API_TOKEN`` are configured.
Identity providers such as Authentik can authenticate using
``Authorization: Bearer <API_TOKEN>`` against ``https://mail.example.com/api/scim/v2``.

Supported endpoints:

* ``GET /api/scim/v2/ServiceProviderConfig``, ``GET /api/scim/v2/ResourceTypes``,
  ``GET /api/scim/v2/ResourceTypes/User``, ``GET /api/scim/v2/Schemas``, and
  ``GET /api/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User``
* ``GET /api/scim/v2/Users`` (supports ``startIndex``, ``count``, and equality
  filters on ``userName``, ``id``, ``emails.value``, ``emails[value eq "..."]``,
  and ``active``)
* ``POST /api/scim/v2/Users`` (provisions a user on an existing Mailu domain;
  returns ``409 Conflict`` with ``scimType: "uniqueness"`` if the user already exists)
* ``GET``, ``PUT``, ``PATCH``, and ``DELETE`` on ``/api/scim/v2/Users/{email}``
  with weak ``ETag`` / ``If-Match`` optimistic concurrency support

By default, ``DELETE /api/scim/v2/Users/{email}`` disables the account
(preserving mailbox data) and revokes active web sessions and OAuth2 grants.
Set ``SCIM_DELETE_ACTION=delete`` to permanently delete the user record instead.
