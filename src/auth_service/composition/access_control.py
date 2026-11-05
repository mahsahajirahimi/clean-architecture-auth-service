from sqlalchemy.orm import Session

from auth_service.modules.access_control.infrastructure.identity_reader import (
    IdentityReaderAdapter,
)
from auth_service.modules.identity.application.access_queries import (
    IdentityAccessQueries,
)
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyGroupRepository,
    SqlAlchemyMembershipRepository,
    SqlAlchemyUserRepository,
)


def make_identity_reader(session: Session) -> IdentityReaderAdapter:
    return IdentityReaderAdapter(
        IdentityAccessQueries(
            SqlAlchemyUserRepository(session),
            SqlAlchemyGroupRepository(session),
            SqlAlchemyMembershipRepository(session),
        )
    )
