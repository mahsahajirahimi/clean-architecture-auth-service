# Central Authentication and Authorization Service

University assignment: a simplified, single-realm identity and authorization service.

## Current status

Identity domain entities, application ports/use cases, SQLAlchemy persistence, and
Argon2id password hashing are implemented. HTTP APIs, authentication tokens,
administrator bootstrap, and the Access Control module are still planned.

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
python -m pip install -e .
python -m unittest discover -s tests -v
```

Tests use unittest and temporary SQLite databases. No running database server is
required. Test package markers allow discovery from both the repository root and
`tests/`.

SQLAlchemy 2.x provides persistence and transaction management. SQLite keeps the
initial deployment simple. argon2-cffi provides Argon2id password hashing and
verification; passwords are never stored in plaintext by CreateUser.

Schema creation currently uses Base.metadata.create_all after importing Identity
ORM models. Database migrations and a runnable API entry point are not yet added.
Administrative endpoints should be introduced together with authentication and a
secure administrator bootstrap.
