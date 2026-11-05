"""Local operator command; this does not grant administrator permissions."""

import os
from getpass import getpass

from sqlalchemy.exc import IntegrityError

from auth_service.composition.schema import create_schema
from auth_service.infrastructure.persistence.database import (
    make_engine,
    make_session_factory,
)
from auth_service.modules.identity.application.exceptions import IdentityError
from auth_service.modules.identity.application.use_cases.create_user import CreateUser
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyUserRepository,
)
from auth_service.modules.identity.infrastructure.security.argon2_password_hasher import (
    Argon2PasswordHasher,
)


def main() -> None:
    username = input("Username: ")
    password = getpass("Password: ")
    if password != getpass("Confirm password: "):
        raise SystemExit("Passwords do not match")
    if len(password) > 1024 or len(username.strip()) > 255:
        raise SystemExit("Username or password exceeds the login input limit")
    engine = make_engine(
        os.environ.get("AUTH_DATABASE_URL", "sqlite:///auth_service.db")
    )
    try:
        create_schema(engine)
        with make_session_factory(engine).begin() as session:
            user = CreateUser(
                SqlAlchemyUserRepository(session), Argon2PasswordHasher()
            ).execute(username, password)
        print(f"Created user {user.username} ({user.id})")
    except IdentityError as error:
        raise SystemExit(str(error)) from None
    except IntegrityError:
        raise SystemExit(
            "User could not be created because of a data conflict"
        ) from None
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
