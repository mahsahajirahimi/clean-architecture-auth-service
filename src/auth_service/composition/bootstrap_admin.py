"""One-time local bootstrap; never exposed as an HTTP endpoint."""

import os
from getpass import getpass

from sqlalchemy.exc import IntegrityError

from auth_service.infrastructure.persistence.database import (
    Base,
    make_engine,
    make_session_factory,
)
from auth_service.modules.identity.application.exceptions import (
    BootstrapAlreadyCompletedError,
    IdentityError,
)
from auth_service.modules.identity.application.use_cases.bootstrap_administrator import (
    BootstrapAdministrator,
)
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyAdministratorRepository,
    SqlAlchemyUserRepository,
)
from auth_service.modules.identity.infrastructure.security.argon2_password_hasher import (
    Argon2PasswordHasher,
)


def main() -> None:
    engine = make_engine(
        os.environ.get("AUTH_DATABASE_URL", "sqlite:///auth_service.db")
    )
    try:
        Base.metadata.create_all(engine)
        sessions = make_session_factory(engine)
        # Reject repeated bootstrap before prompting for credentials.
        with sessions() as session:
            if SqlAlchemyAdministratorRepository(session).get_user_id() is not None:
                raise BootstrapAlreadyCompletedError(
                    "Administrator bootstrap has already completed"
                )
        username = input("Administrator username: ")
        password = getpass("Password: ")
        if password != getpass("Confirm password: "):
            raise SystemExit("Passwords do not match")
        with sessions.begin() as session:
            user = BootstrapAdministrator(
                SqlAlchemyUserRepository(session),
                SqlAlchemyAdministratorRepository(session),
                Argon2PasswordHasher(),
            ).execute(username, password)
        print(f"Created initial administrator {user.username} ({user.id})")
    except IdentityError as error:
        raise SystemExit(str(error)) from None
    except IntegrityError:
        # A concurrent bootstrap may win after our initial existence check.
        # The transaction context has already rolled back the losing user's insert.
        raise SystemExit(
            "Administrator bootstrap conflicted with another operation; no changes were committed"
        ) from None
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
