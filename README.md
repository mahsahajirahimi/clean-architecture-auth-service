# Central Authentication and Authorization Service

University assignment: a simplified, single-realm identity and authorization service.

## Current status

Identity domain entities, application ports/use cases, SQLAlchemy persistence, and
Argon2id password hashing, JWT authentication, and the first FastAPI endpoints
are implemented. One-time administrator bootstrap and protected user/group
creation, paginated user/group reads, membership addition/removal, and user
activation/deactivation APIs are implemented. The Access Control domain model
and its pure authorization policy and application use cases are implemented.
SQLAlchemy persistence and the concrete Identity adapter are also implemented.
Protected Access Control HTTP APIs are implemented for catalog creation/listing,
grant assignment/revocation, current-user access checks, and administrator
inspection of other users. Final security/requirements review, migration decisions,
and the university report remain.

## Architecture

One deployable Modular Monolith with Clean Architecture inside each module.
Domain entities have no framework or database dependencies. Application use cases
depend on ports; Infrastructure implements those ports. Identity owns users,
groups, and memberships. Access Control will own scopes, permissions, and grants.

Repositories flush writes but do not commit. The caller owns the transaction:

```python
with SessionLocal.begin() as session:
    # Construct repositories with this session and execute use cases here.
    ...
```

Exiting normally commits; an exception rolls back the operation. Database
constraints enforce unique usernames/group names, unique memberships, and valid
membership references. Deleting a user or group cascades to its memberships.
Repositories surface database constraint failures as SQLAlchemy IntegrityError.
The HTTP composition boundary rolls back the request transaction and translates
these to a generic `409` without exposing SQL or parameters. The initial
administrator cannot be deleted while referenced by the bootstrap record.

## Setup and tests

Requires Python 3.11+.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip --isolated install --index-url https://pypi.org/simple -e ".[test]"
python -m unittest discover -s tests -v
```

The explicit PyPI index avoids relying on a locally configured package mirror.
The `test` extra installs HTTP clients for the FastAPI TestClient.

Tests use unittest and temporary SQLite databases. No running database server is
required. Test package markers allow discovery from both the repository root and
`tests/`.

SQLAlchemy 2.x provides persistence and transaction management. SQLite keeps the
initial deployment simple. argon2-cffi provides Argon2id password hashing and
verification; passwords are never stored in plaintext by CreateUser.

## Run locally

Activate `.venv` and run the following from the repository root. Generate the
signing secret once for the terminal session (at least 32 random bytes); keep it
out of Git:

```sh
export AUTH_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
# First setup only: create the initial administrator with a new username.
python -m auth_service.composition.bootstrap_admin
python -m uvicorn auth_service.composition.app:create_app --factory --reload
```

The bootstrap command prompts for an administrator username and password without
displaying the password. It requires local database access and is not exposed
through HTTP. It creates a new user; an existing user with the same name is never
promoted or overwritten. Run bootstrap once per database, not on every start.
Nothing is seeded automatically at server startup.

Bootstrap creates the user and the singleton `identity_administrator` record in
one transaction. The database restricts the record to primary key `1`; concurrent
bootstrap attempts can commit only one initial administrator. A losing attempt
rolls back its newly created user. Repeat bootstrap is refused even if the
administrator has been deactivated. There is no automatic password reset.

This stage supports one initial administrator. Adding more administrators,
transferring administrator access, and recovery are not exposed by the current
API. The bootstrap record is an Identity administration policy, separate from
the future Access Control scopes and permissions. A group named `admin` grants
no special privileges.

The earlier `python -m auth_service.composition.create_user` command remains an
optional local tool for ordinary development users and never grants admin access.

Open http://127.0.0.1:8000/docs for interactive API documentation. Call
`POST /auth/login` with JSON `{"username": "your-user", "password": "your-password"}`.
Copy the returned access token into the Swagger **Authorize** dialog, then call
`GET /auth/me`. Passwords preserve whitespace; usernames are trimmed.

With the initial administrator's token you can also call:

| Endpoint | JSON body | Result |
| --- | --- | --- |
| `POST /users` | `{"username": "ali", "password": "choose-a-password"}` | `201`: user ID, username, active status |
| `POST /groups` | `{"name": "staff"}` | `201`: group ID and name |
| `POST /groups/{group_id}/members` | `{"user_id": "user-uuid"}` | `201`: user ID and group ID |
| `GET /users?limit=50&offset=0` | None | `200`: array of users |
| `GET /users/{user_id}` | None | `200`: user ID, username, active status |
| `GET /groups?limit=50&offset=0` | None | `200`: array of groups |
| `GET /groups/{group_id}` | None | `200`: group ID and name |
| `PATCH /users/{user_id}/status` | `{"is_active": false}` or `{"is_active": true}` | `200`: updated user |
| `DELETE /groups/{group_id}/members/{user_id}` | None | `204`: empty response |

All management endpoints above require an active administrator: `401` for missing/invalid
credentials or an inactive user, `403` for an authenticated ordinary user.
Missing users/groups return `404`; duplicate usernames, group names, or
memberships return `409`. Schema errors return `422`; blank strings that reach
the application are rejected with `400`. A request containing an unsupported
field such as `is_admin` is rejected. No password hashes appear in responses.

User/group list endpoints default to `limit=50` and `offset=0`, with limits from
1 to 100 and nonnegative offsets. Results are ordered by username/group name,
then ID. User lists include inactive users; an empty page returns `[]`.

Membership removal deletes only the selected membership. It preserves the user,
the group, and memberships in other groups. Missing users, groups, or membership
return `404`, including a second deletion of the same membership. The user may be
added to that group again later.

Status requests accept only a JSON boolean. Repeating the current status is a
successful no-op. Deactivating the initial administrator returns `409` to avoid
locking out the only administrator. Disabling ordinary users blocks both login
and authenticated requests immediately on subsequent requests. Reactivation
allows login and restores use of existing unexpired tokens; persistent token
revocation is not implemented in this stage.

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUTH_JWT_SECRET` | Required | HS256 signing key, at least 32 bytes |
| `AUTH_DATABASE_URL` | `sqlite:///auth_service.db` | Database shared by the API and local command |
| `AUTH_JWT_ISSUER` | `auth-service` | Expected token issuer |
| `AUTH_JWT_AUDIENCE` | `auth-service-api` | Expected token audience |
| `AUTH_TOKEN_LIFETIME_SECONDS` | `900` | Access-token lifetime, between 60 and 3600 seconds |

Use the same signing secret across restarts if existing tokens should stay valid.
Changing it invalidates tokens. For a persistent local secret, store it outside
Git and load it into the environment; `.env` files are not loaded automatically.

## Authentication boundaries

- Login and current-user use cases depend on Application ports, not FastAPI or
  PyJWT. The Composition Root connects repositories, security adapters, and
  HTTP dependencies. Each request owns its SQLAlchemy session and transaction;
  transaction cleanup runs before the response is sent.
- Tokens use a fixed HS256 algorithm, expiry, issuer, audience, UUID subject,
  issuance/not-before times, a unique token ID, and an access-token purpose.
  Tokens contain no password hashes or permissions. This is a custom JSON login
  API, not a complete OAuth2/OIDC implementation.
- Each authenticated request reloads the user from the database. Deleted or
  inactive users are rejected even when their token has not expired. Permissions
  and group-based authorization are evaluated through the Access Control
  application layer using current Identity data.
- Unknown users, incorrect passwords, and inactive users receive the same `401`
  response. Unknown users still perform a dummy password verification. Malformed
  request bodies receive `422` without echoing submitted values. Successful
  responses expose only the explicit response schemas.
- Usernames at login are limited to 255 characters and passwords to 1024.
  User and group names are limited to 255 characters in creation use cases.
  User creation through HTTP requires administrator access; there is no public registration.
- Administrator access is read from the database on every administrative request;
  it is not inferred from a username, group name, or JWT role claim.
- Refresh tokens, logout/revocation, and login throttling are not implemented
  in this stage. Use HTTPS when
  deploying beyond local development.

The app currently creates missing tables with `Base.metadata.create_all` at
startup. Database migrations are still planned.

## Access Control domain

The domain is independent of Identity, FastAPI, SQLAlchemy, and JWT. It currently
provides immutable entities and a pure authorization policy. HTTP access checks
call this policy through Application. Identity administrator checks continue to
use their own policy.

- `Scope(id, name)` identifies a resource area, such as `orders`.
- `Permission(id, scope_id, name)` identifies an operation in one scope, such as
  `orders:read`. The same operation name in another scope is a different permission.
- `Grant(subject_type, subject_id, target_type, target_id)` assigns either a
  permission or a scope to either a user or a group. Subject and target types are
  explicit enums; there are no special group names or wildcard strings. A grant's
  identity is the combination of its four fields, so it needs no separate ID.

Names are case-sensitive, nonblank, already trimmed strings of at most 255
characters. IDs must be UUIDs. Scope-name uniqueness, permission-name uniqueness
within a scope, reference existence, and duplicate grants are checked by the
application use cases. Database constraints additionally enforce catalog
uniqueness, grant uniqueness, and references within Access Control. Entities do not query a database or check
Identity records themselves.

`AccessPolicy.effective_permissions(...)` returns an immutable set of permission
IDs for a current snapshot of an identified user's active status, group IDs,
scopes, permissions, and grants. `allows(permission_id, ...)` checks membership
in that effective set. The application obtains this snapshot through ports for
current Identity membership/status data, not JWT permission claims or direct
access to Identity tables. The Infrastructure adapter connects this port to
Identity application queries.

The policy rules are:

1. An inactive user always has no effective permissions. An active user with no
   matching grants also has no permissions; there is no implicit administrator
   bypass for business-resource permissions.
2. Direct user grants and grants to any current group are combined. Grants for
   other users or groups are ignored. A user UUID and group UUID are distinct
   namespaces even if their values happen to be equal.
3. A permission grant covers only that permission ID in its own scope. A scope
   grant covers **all current and subsequently added permissions** in that scope.
   Assign individual permissions when narrower access is intended.
4. This is an additive allow model with no explicit deny. Revoking one grant
   removes only that source of access. A direct grant, another group grant, or a
   scope grant can still provide the permission.
5. Each evaluation uses its supplied snapshot without caching. Membership removal
   or grant revocation changes the next evaluation. A grant to a permission or
   scope absent from the current catalog cannot confer access. A scope with no
   configured permissions grants no operation until permissions are added.

## Access Control application

The application layer uses `Protocol` ports and no FastAPI, SQLAlchemy, JWT, or
Identity implementation imports. The current use cases are:

| Use case | Behavior |
| --- | --- |
| `CreateScope` | Trim/validate the name, check global name uniqueness, create and save a scope |
| `CreatePermission` | Validate the parent scope, check name uniqueness within that scope, create and save a permission |
| `ListScopes` / `ListPermissions` | Return bounded catalog pages; permission lists are filtered to one existing scope |
| `AssignGrant` | Validate the user/group and scope/permission target, reject a duplicate grant, save it |
| `RevokeGrant` | Remove the exact composite grant; report a missing grant explicitly |
| `GetEffectivePermissions` | Read fresh Identity context and catalog/grants, then evaluate the domain policy |
| `CheckAccess` | Return whether the requested permission ID is in the user's effective set |

`ScopeRepository`, `PermissionRepository`, and `GrantRepository` own the Access
Control data contracts. `IdentityReader` supplies an immutable `UserAccessContext`
(user ID, active flag, current group IDs) and group-existence checks. No password
hashes or Identity entities cross this boundary. The reader's returned user ID
must match the requested user; a mismatch raises `IdentityContextError` rather
than using another user's status or groups.

Assignments to existing inactive users are allowed, but checks for inactive users
return no permissions without querying grants or the catalog. Unknown users raise
`UserNotFoundError`; unknown permission IDs are denied. The context, grants, and
catalog are read again on each evaluation. Lookup or persistence errors propagate;
there is no fallback to cached authorization or successful access.

Revocation intentionally requires only the grant key and repository. It can clean
up stale grants even after the corresponding user/group or scope/permission is
gone. A second revocation raises `GrantNotFoundError`. Grant keys use explicit
`SubjectType` and `GrantTargetType` enum values; Presentation validates and
converts their HTTP string representations.

Transactions remain caller-owned. The new repository ports have no `commit` or
`rollback`. Application existence/uniqueness checks are not sufficient for
concurrent writes: the SQLAlchemy adapters enforce constraints and surface
IntegrityError to the caller-owned transaction boundary. Existing HTTP wiring
rolls back such conflicts before a response is sent, including Access Control
responses. Access Control Presentation maps its own expected application errors
to HTTP statuses without depending on Identity exceptions.

## Access Control infrastructure

Four SQLAlchemy tables store the Access Control data:

| Table | Constraints |
| --- | --- |
| `access_scopes` | UUID primary key, globally unique nonempty name of at most 255 characters |
| `access_permissions` | UUID primary key, scope foreign key, unique `(scope_id, name)` |
| `access_scope_grants` | Composite primary key `(subject_type, subject_id, scope_id)` and scope foreign key |
| `access_permission_grants` | Composite primary key `(subject_type, subject_id, permission_id)` and permission foreign key |

Scope and permission grants use separate tables so each target has a real foreign
key, without nullable polymorphic target columns. Subject types are restricted to
`user` and `group`. Deleting a scope cascades to its permissions and all related
grants; deleting a permission removes its specific grants. Grant removal deletes
only the exact subject/type/target combination. Repositories flush without
committing, and database failures leave rollback to the caller's transaction.

Identity owns subject records. Access Control does not declare foreign keys to
Identity tables. Subject existence is checked through `IdentityReader` during
assignment. If a subject is deleted outside the currently exposed APIs, its stale
grant may remain for explicit revocation; it cannot give a missing user or a
nonmember group access. A newly created user with the same username has a new UUID
and does not inherit the old user's grants.

`IdentityAccessQueries` is a read-only Identity Application service built from
Identity's own repository ports. Its immutable DTO contains only a user UUID,
active status, and current group UUIDs. `IdentityReaderAdapter` maps that DTO to
Access Control's contract and never imports Identity ORM models or runs SQL
against Identity tables. `composition.access_control.make_identity_reader`
connects the adapter to the concrete Identity repositories with the request's
session. Membership lookup is implemented inside Identity persistence.

`composition.schema.create_schema` explicitly registers both modules' tables and
is shared by server startup and both local user/bootstrap commands. It adds the
new tables to an existing Identity database without replacing data. It is still
schema initialization, not a migration system for changing existing columns.

Integration tests use temporary SQLite databases and real adapters to verify
round trips, unique and foreign-key constraints, rollback, cascade deletion,
subject filtering, direct/group permission union, revocation, current membership
and activity changes, and schema initialization over existing Identity data.

## Access Control API

All paths below use Bearer authentication. Use the token from `/auth/login` in
Swagger's **Authorize** dialog at `/docs`. Administrative operations require the
current Identity administrator; having an application scope/permission does not
grant administrator status.

| Method and path | Caller | Body/result |
| --- | --- | --- |
| `POST /access-control/scopes` | Administrator | `{"name": "orders"}` -> `201` scope |
| `GET /access-control/scopes` | Administrator | `200` scope array |
| `POST /access-control/scopes/{scope_id}/permissions` | Administrator | `{"name": "read"}` -> `201` permission |
| `GET /access-control/scopes/{scope_id}/permissions` | Administrator | `200` permission array for that scope |
| `POST /access-control/grants` | Administrator | Grant body below -> `201` grant |
| `DELETE /access-control/grants/{subject_type}/{subject_id}/{target_type}/{target_id}` | Administrator | `204`, no body |
| `GET /access-control/me/permissions` | Active user | `200` own user ID and sorted permission ID array |
| `POST /access-control/me/check` | Active user | `{"permission_id": "permission-uuid"}` -> `200` decision |
| `GET /access-control/users/{user_id}/permissions` | Administrator | `200` target user ID and effective permission IDs |
| `POST /access-control/users/{user_id}/check` | Administrator | `{"permission_id": "permission-uuid"}` -> `200` decision for the target user |

Grant creation uses this shape (replace placeholder IDs with returned UUIDs):

```json
{
  "subject_type": "user",
  "subject_id": "user-uuid",
  "target_type": "permission",
  "target_id": "permission-uuid"
}
```

Use `subject_type: "group"` to assign to a group, or `target_type: "scope"`
with a scope UUID to grant all current and future operations in that scope.
The delete path uses the same four values as creation, so no separate grant ID
is needed. A second deletion returns `404`.

Catalog lists accept `limit` (default 50, range 1-100) and `offset` (default 0,
nonnegative). Scopes are ordered by name/ID; permissions are filtered to the
requested scope and ordered by name/ID. Empty pages return `[]`.

Self-service paths take the user ID from the validated current user, not a body,
query parameter, or JWT permission claim. Supplying an extra `user_id` in the
check body is rejected. The `/users/{user_id}` inspection paths remain
administrator-only even if the requested ID is the caller's own ID.

A permission decision has the shape:

```json
{
  "user_id": "user-uuid",
  "permission_id": "permission-uuid",
  "allowed": false
}
```

A valid request for an ungranted or unknown permission returns `200` with
`allowed: false`; this is distinct from `401` for authentication failure or
`403` for trying to perform an administrative operation as an ordinary user.
Missing catalog entries, grant subjects, grants, or target users return `404`.
Duplicate names/grants and database conflicts return `409`. Schema errors
return `422`, blank application names return `400`, and internal Identity-context
contract failures return a sanitized `500`. Responses use `Cache-Control:
no-store`.

An administrator inspecting an inactive target user sees no effective permissions
and `allowed: false`. The inactive user cannot call authenticated self-service
routes and receives `401`. Administrator status itself does not imply business
permissions: the administrator also needs grants for a positive `/me/check`.

### Manual scenario in Swagger

1. Bootstrap an administrator locally, start the server, log in as administrator,
   and authorize its token in `/docs`.
2. Create an ordinary user and a group through the Identity APIs; create an
   `orders` scope and a `read` permission through Access Control. Retain the UUIDs.
3. Assign the `read` permission to the group, then add the user to that group.
4. Log in as the ordinary user and authorize that token. `/access-control/me/check`
   with the permission UUID returns `allowed: true`.
5. As administrator, remove the group membership or revoke the group grant.
   Repeat the check with the same ordinary-user token: it returns `allowed: false`
   unless another direct/group/scope grant still supplies that permission.

The API tests exercise these operations through HTTP and temporary SQLite,
including actor isolation, current-token behavior after changes, validation,
unique-constraint races, and rollback before successful responses.

## Library choices

FastAPI provides HTTP routing, validation, dependency injection, and OpenAPI.
PyJWT implements JWT signing and claim verification. Uvicorn runs the ASGI app.
HTTP client packages in the test extra support TestClient only; they are not
application dependencies.
