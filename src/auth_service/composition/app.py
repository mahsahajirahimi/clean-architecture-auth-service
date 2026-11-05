from collections.abc import Iterator
from contextlib import asynccontextmanager
from secrets import token_urlsafe
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from auth_service.composition.access_control import configure_access_control
from auth_service.composition.schema import create_schema
from auth_service.composition.settings import Settings
from auth_service.composition.web import configure_web
from auth_service.infrastructure.persistence.database import (
    make_engine,
    make_session_factory,
)
from auth_service.modules.identity.application.exceptions import DataConflictError
from auth_service.modules.identity.application.use_cases.add_user_to_group import (
    AddUserToGroup,
)
from auth_service.modules.identity.application.use_cases.create_group import CreateGroup
from auth_service.modules.identity.application.use_cases.create_user import CreateUser
from auth_service.modules.identity.application.use_cases.get_current_user import (
    GetCurrentUser,
)
from auth_service.modules.identity.application.use_cases.get_group import GetGroup
from auth_service.modules.identity.application.use_cases.get_user import GetUser
from auth_service.modules.identity.application.use_cases.list_group_members import (
    ListGroupMembers,
)
from auth_service.modules.identity.application.use_cases.list_groups import ListGroups
from auth_service.modules.identity.application.use_cases.list_user_groups import (
    ListUserGroups,
)
from auth_service.modules.identity.application.use_cases.list_users import ListUsers
from auth_service.modules.identity.application.use_cases.login import Login
from auth_service.modules.identity.application.use_cases.remove_user_from_group import (
    RemoveUserFromGroup,
)
from auth_service.modules.identity.application.use_cases.require_administrator import (
    RequireAdministrator,
)
from auth_service.modules.identity.application.use_cases.set_user_status import (
    SetUserStatus,
)
from auth_service.modules.identity.domain.entities.user import User
from auth_service.modules.identity.infrastructure.persistence.repositories import (
    SqlAlchemyAdministratorRepository,
    SqlAlchemyGroupRepository,
    SqlAlchemyMembershipRepository,
    SqlAlchemyUserRepository,
)
from auth_service.modules.identity.infrastructure.security.argon2_password_hasher import (
    Argon2PasswordHasher,
)
from auth_service.modules.identity.infrastructure.security.jwt_tokens import JwtTokens
from auth_service.modules.identity.presentation.admin_routes import create_admin_router
from auth_service.modules.identity.presentation.errors import register_error_handlers
from auth_service.modules.identity.presentation.management_routes import (
    create_management_router,
)
from auth_service.modules.identity.presentation.routes import create_router
from auth_service.modules.identity.presentation.security import get_bearer_token


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings if settings is not None else Settings.from_environment()
    tokens = JwtTokens(
        settings.jwt_secret,
        settings.jwt_issuer,
        settings.jwt_audience,
        settings.token_lifetime_seconds,
    )
    engine = make_engine(settings.database_url)
    sessions = make_session_factory(engine)
    passwords = Argon2PasswordHasher()
    dummy_password_hash = passwords.hash(token_urlsafe(32))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            create_schema(engine)
            yield
        finally:
            engine.dispose()

    app = FastAPI(title="Authentication Service", version="0.1.0", lifespan=lifespan)

    def get_session() -> Iterator[Session]:
        try:
            with sessions.begin() as session:
                yield session
        except IntegrityError:
            # Translate persistence conflicts only after the context rolled back.
            raise DataConflictError("Operation conflicts with existing data") from None

    # End the transaction before a successful HTTP response is sent.
    SessionDependency = Annotated[Session, Depends(get_session, scope="function")]

    def get_login(session: SessionDependency) -> Login:
        return Login(
            SqlAlchemyUserRepository(session), passwords, tokens, dummy_password_hash
        )

    def get_current_user(
        session: SessionDependency,
        token: Annotated[str, Depends(get_bearer_token)],
    ) -> User:
        return GetCurrentUser(SqlAlchemyUserRepository(session), tokens).execute(token)

    def get_administrator(
        user: Annotated[User, Depends(get_current_user)],
        session: SessionDependency,
    ) -> User:
        return RequireAdministrator(SqlAlchemyAdministratorRepository(session)).execute(
            user
        )

    def get_create_user(session: SessionDependency) -> CreateUser:
        return CreateUser(SqlAlchemyUserRepository(session), passwords)

    def get_create_group(session: SessionDependency) -> CreateGroup:
        return CreateGroup(SqlAlchemyGroupRepository(session))

    def get_add_member(session: SessionDependency) -> AddUserToGroup:
        return AddUserToGroup(
            SqlAlchemyUserRepository(session),
            SqlAlchemyGroupRepository(session),
            SqlAlchemyMembershipRepository(session),
        )

    def get_user_reader(session: SessionDependency) -> GetUser:
        return GetUser(SqlAlchemyUserRepository(session))

    def get_user_list(session: SessionDependency) -> ListUsers:
        return ListUsers(SqlAlchemyUserRepository(session))

    def get_group_reader(session: SessionDependency) -> GetGroup:
        return GetGroup(SqlAlchemyGroupRepository(session))

    def get_group_list(session: SessionDependency) -> ListGroups:
        return ListGroups(SqlAlchemyGroupRepository(session))

    def get_set_user_status(session: SessionDependency) -> SetUserStatus:
        return SetUserStatus(
            SqlAlchemyUserRepository(session),
            SqlAlchemyAdministratorRepository(session),
        )

    def get_remove_member(session: SessionDependency) -> RemoveUserFromGroup:
        return RemoveUserFromGroup(
            SqlAlchemyUserRepository(session),
            SqlAlchemyGroupRepository(session),
            SqlAlchemyMembershipRepository(session),
        )

    def get_user_groups(session: SessionDependency) -> ListUserGroups:
        return ListUserGroups(
            SqlAlchemyUserRepository(session), SqlAlchemyMembershipRepository(session)
        )

    def get_group_members(session: SessionDependency) -> ListGroupMembers:
        return ListGroupMembers(
            SqlAlchemyGroupRepository(session), SqlAlchemyMembershipRepository(session)
        )

    app.include_router(
        create_management_router(
            get_administrator,
            get_user_reader,
            get_user_list,
            get_group_reader,
            get_group_list,
            get_set_user_status,
            get_remove_member,
            get_user_groups,
            get_group_members,
        )
    )
    app.include_router(create_router(get_login, get_current_user))
    app.include_router(
        create_admin_router(
            get_administrator, get_create_user, get_create_group, get_add_member
        )
    )

    def get_current_user_id(user: Annotated[User, Depends(get_current_user)]) -> UUID:
        return user.id

    register_error_handlers(app)
    configure_access_control(app, get_session, get_current_user_id, get_administrator)
    configure_web(app)
    return app
