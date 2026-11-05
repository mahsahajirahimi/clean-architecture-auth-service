from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from auth_service.modules.identity.domain.entities.group import Group
from auth_service.modules.identity.domain.entities.membership import GroupMembership
from auth_service.modules.identity.domain.entities.user import User
from auth_service.modules.identity.infrastructure.persistence.models import (
    AdministratorModel,
    GroupMembershipModel,
    GroupModel,
    UserModel,
)


class SqlAlchemyUserRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _to_domain(model: UserModel | None) -> User | None:
        if model is None:
            return None
        return User(UUID(model.id), model.username, model.password_hash, model.is_active)

    def get_by_id(self, user_id: UUID) -> User | None:
        return self._to_domain(self.session.get(UserModel, str(user_id)))

    def get_by_username(self, username: str) -> User | None:
        return self._to_domain(self.session.scalar(
            select(UserModel).where(UserModel.username == username)
        ))

    def save(self, user: User) -> None:
        self.session.merge(UserModel(
            id=str(user.id), username=user.username,
            password_hash=user.password_hash, is_active=user.is_active,
        ))
        self.session.flush()


class SqlAlchemyGroupRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _to_domain(model: GroupModel | None) -> Group | None:
        if model is None:
            return None
        return Group(UUID(model.id), model.name)

    def get_by_id(self, group_id: UUID) -> Group | None:
        return self._to_domain(self.session.get(GroupModel, str(group_id)))

    def get_by_name(self, name: str) -> Group | None:
        return self._to_domain(self.session.scalar(
            select(GroupModel).where(GroupModel.name == name)
        ))

    def save(self, group: Group) -> None:
        self.session.merge(GroupModel(id=str(group.id), name=group.name))
        self.session.flush()


class SqlAlchemyMembershipRepository:
    def __init__(self, session: Session):
        self.session = session

    def exists(self, user_id: UUID, group_id: UUID) -> bool:
        return self.session.get(
            GroupMembershipModel, (str(user_id), str(group_id))
        ) is not None

    def save(self, membership: GroupMembership) -> None:
        self.session.add(GroupMembershipModel(
            user_id=str(membership.user_id), group_id=str(membership.group_id),
        ))
        self.session.flush()


class SqlAlchemyAdministratorRepository:
    def __init__(self, session: Session):
        self.session = session

    def get_user_id(self) -> UUID | None:
        model = self.session.get(AdministratorModel, 1)
        return UUID(model.user_id) if model is not None else None

    def initialize(self, user_id: UUID) -> None:
        self.session.add(AdministratorModel(id=1, user_id=str(user_id)))
        self.session.flush()
