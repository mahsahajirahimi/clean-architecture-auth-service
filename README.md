# Central Authentication and Authorization Service

University assignment: a simplified, single-realm identity and authorization service.

## Current status

Identity domain entities, application ports/use cases, SQLAlchemy persistence, and
Argon2id password hashing, JWT authentication, and the first FastAPI endpoints
are implemented. Administrator bootstrap, administrative APIs, and the Access
Control module are still planned.

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
Constraint failures currently surface as SQLAlchemy IntegrityError; a future HTTP
boundary must translate expected conflicts after rollback without exposing SQL.

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
python -m auth_service.composition.create_user
python -m uvicorn auth_service.composition.app:create_app --factory --reload
```

The local command prompts for a username and password without displaying the
password, and creates an ordinary active user. It requires local database access
and does not grant administrator privileges. It is a development/operator tool,
not the future administrator bootstrap. Reusing a username fails without changing
the existing user. Nothing is seeded automatically at server startup.

Open http://127.0.0.1:8000/docs for interactive API documentation. Call
`POST /auth/login` with JSON `{"username": "your-user", "password": "your-password"}`.
Copy the returned access token into the Swagger **Authorize** dialog, then call
`GET /auth/me`. Passwords preserve whitespace; usernames are trimmed.

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
  and group-based authorization will be implemented in Access Control.
- Unknown users, incorrect passwords, and inactive users receive the same `401`
  response. Unknown users still perform a dummy password verification. Malformed
  request bodies receive `422` without echoing submitted values. Successful
  responses expose only the explicit response schemas.
- Usernames at login are limited to 255 characters and passwords to 1024.
  There is no public user registration or administrative HTTP endpoint yet.
- Refresh tokens, logout/revocation, login throttling, administrator bootstrap,
  and access-control APIs are not implemented in this stage. Use HTTPS when
  deploying beyond local development.

The app currently creates missing tables with `Base.metadata.create_all` at
startup. Database migrations are still planned.

## Library choices

FastAPI provides HTTP routing, validation, dependency injection, and OpenAPI.
PyJWT implements JWT signing and claim verification. Uvicorn runs the ASGI app.
HTTP client packages in the test extra support TestClient only; they are not
application dependencies.
