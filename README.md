# Authentication and Authorization Service

Single-realm authentication and access control service for the university assignment.

## Features

- Users, groups, and multiple group memberships.
- Scope and permission assignment/revocation for users and groups.
- Effective access checks using current grants and memberships.
- JWT login, Argon2id password hashing, and protected management APIs.

## Architecture

Modular Monolith with two modules: `identity` and `access_control`.
Each follows Clean Architecture: Domain, Application, Infrastructure, and Presentation.
The Composition Root connects dependencies. Built with Python 3.11+, FastAPI,
SQLAlchemy, and SQLite.

## Run

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[test]"
export AUTH_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
# Run only once per database:
python -m auth_service.composition.bootstrap_admin
python -m uvicorn auth_service.composition.app:create_app --factory --reload
```

- Dashboard: http://127.0.0.1:8000/ui/
- API documentation: http://127.0.0.1:8000/docs
- Default database: `auth_service.db`; override with `AUTH_DATABASE_URL`.
- Keep the signing secret private and stable across restarts to preserve valid tokens.

## Tests

```sh
python -m unittest discover -s tests -v
```

224 tests: 106 unit, 60 integration, and 58 API tests.

