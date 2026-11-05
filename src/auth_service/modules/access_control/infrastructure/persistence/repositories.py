from uuid import UUID

from sqlalchemy import and_, delete, literal, or_, select, union_all
from sqlalchemy.orm import Session

from auth_service.modules.access_control.domain.entities.grant import (
    Grant,
    GrantTargetType,
    SubjectType,
)
from auth_service.modules.access_control.domain.entities.permission import Permission
from auth_service.modules.access_control.domain.entities.scope import Scope
from auth_service.modules.access_control.infrastructure.persistence.models import (
    PermissionGrantModel,
    PermissionModel,
    ScopeGrantModel,
    ScopeModel,
)


class SqlAlchemyScopeRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _to_domain(model: ScopeModel) -> Scope:
        return Scope(UUID(model.id), model.name)

    def get_by_id(self, scope_id: UUID) -> Scope | None:
        model = self.session.get(ScopeModel, str(scope_id))
        return self._to_domain(model) if model is not None else None

    def get_by_name(self, name: str) -> Scope | None:
        model = self.session.scalar(select(ScopeModel).where(ScopeModel.name == name))
        return self._to_domain(model) if model is not None else None

    def list_all(self) -> list[Scope]:
        return [
            self._to_domain(model)
            for model in self.session.scalars(
                select(ScopeModel).order_by(ScopeModel.name, ScopeModel.id)
            )
        ]

    def list(self, limit: int, offset: int) -> list[Scope]:
        rows = self.session.scalars(
            select(ScopeModel)
            .order_by(ScopeModel.name, ScopeModel.id)
            .limit(limit)
            .offset(offset)
        )
        return [self._to_domain(model) for model in rows]

    def save(self, scope: Scope) -> None:
        self.session.merge(ScopeModel(id=str(scope.id), name=scope.name))
        self.session.flush()


class SqlAlchemyPermissionRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _to_domain(model: PermissionModel) -> Permission:
        return Permission(UUID(model.id), UUID(model.scope_id), model.name)

    def get_by_id(self, permission_id: UUID) -> Permission | None:
        model = self.session.get(PermissionModel, str(permission_id))
        return self._to_domain(model) if model is not None else None

    def get_by_scope_and_name(self, scope_id: UUID, name: str) -> Permission | None:
        model = self.session.scalar(
            select(PermissionModel).where(
                PermissionModel.scope_id == str(scope_id), PermissionModel.name == name
            )
        )
        return self._to_domain(model) if model is not None else None

    def list_all(self) -> list[Permission]:
        models = self.session.scalars(
            select(PermissionModel).order_by(
                PermissionModel.scope_id, PermissionModel.name, PermissionModel.id
            )
        )
        return [self._to_domain(model) for model in models]

    def list_by_scope(
        self, scope_id: UUID, limit: int, offset: int
    ) -> list[Permission]:
        rows = self.session.scalars(
            select(PermissionModel)
            .where(PermissionModel.scope_id == str(scope_id))
            .order_by(PermissionModel.name, PermissionModel.id)
            .limit(limit)
            .offset(offset)
        )
        return [self._to_domain(model) for model in rows]

    def save(self, permission: Permission) -> None:
        self.session.merge(
            PermissionModel(
                id=str(permission.id),
                scope_id=str(permission.scope_id),
                name=permission.name,
            )
        )
        self.session.flush()


class SqlAlchemyGrantRepository:
    def __init__(self, session: Session):
        self.session = session

    @staticmethod
    def _model_type(target_type: GrantTargetType):
        return (
            ScopeGrantModel
            if target_type == GrantTargetType.SCOPE
            else PermissionGrantModel
        )

    def exists(self, grant: Grant) -> bool:
        return (
            self.session.get(
                self._model_type(grant.target_type),
                (grant.subject_type.value, str(grant.subject_id), str(grant.target_id)),
            )
            is not None
        )

    def save(self, grant: Grant) -> None:
        self.session.add(
            self._model_type(grant.target_type)(
                subject_type=grant.subject_type.value,
                subject_id=str(grant.subject_id),
                target_id=str(grant.target_id),
            )
        )
        self.session.flush()

    def remove(self, grant: Grant) -> bool:
        model = self._model_type(grant.target_type)
        result = self.session.execute(
            delete(model).where(
                model.subject_type == grant.subject_type.value,
                model.subject_id == str(grant.subject_id),
                model.target_id == str(grant.target_id),
            )
        )
        self.session.flush()
        return result.rowcount == 1

    def list_for_subject(
        self, subject_type: SubjectType, subject_id: UUID, limit: int, offset: int
    ) -> list[Grant]:
        queries = []
        for target_type, model in [
            (GrantTargetType.SCOPE, ScopeGrantModel),
            (GrantTargetType.PERMISSION, PermissionGrantModel),
        ]:
            queries.append(
                select(
                    literal(target_type.value).label("target_type"),
                    model.subject_type.label("subject_type"),
                    model.subject_id.label("subject_id"),
                    model.target_id.label("target_id"),
                ).where(
                    model.subject_type == subject_type.value,
                    model.subject_id == str(subject_id),
                )
            )
        rows = self.session.execute(
            union_all(*queries)
            .order_by("target_type", "target_id")
            .limit(limit)
            .offset(offset)
        )
        return [
            Grant(
                SubjectType(row.subject_type),
                UUID(row.subject_id),
                GrantTargetType(row.target_type),
                UUID(row.target_id),
            )
            for row in rows
        ]

    def list_for_user(self, user_id: UUID, group_ids: frozenset[UUID]) -> list[Grant]:
        grants = []
        for target_type, model in [
            (GrantTargetType.SCOPE, ScopeGrantModel),
            (GrantTargetType.PERMISSION, PermissionGrantModel),
        ]:
            matches = [
                and_(
                    model.subject_type == SubjectType.USER.value,
                    model.subject_id == str(user_id),
                )
            ]
            if group_ids:
                matches.append(
                    and_(
                        model.subject_type == SubjectType.GROUP.value,
                        model.subject_id.in_(
                            sorted(str(group_id) for group_id in group_ids)
                        ),
                    )
                )
            rows = self.session.scalars(
                select(model)
                .where(or_(*matches))
                .order_by(model.subject_type, model.subject_id, model.target_id)
            )
            grants.extend(
                Grant(
                    SubjectType(row.subject_type),
                    UUID(row.subject_id),
                    target_type,
                    UUID(row.target_id),
                )
                for row in rows
            )
        return grants
