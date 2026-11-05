from sqlalchemy import CheckConstraint, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from auth_service.infrastructure.persistence.database import Base


class ScopeModel(Base):
    __tablename__ = "access_scopes"
    __table_args__ = (
        CheckConstraint(
            "length(name) BETWEEN 1 AND 255", name="ck_access_scope_name_length"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)


class PermissionModel(Base):
    __tablename__ = "access_permissions"
    __table_args__ = (
        UniqueConstraint("scope_id", "name", name="uq_access_permission_scope_name"),
        CheckConstraint(
            "length(name) BETWEEN 1 AND 255", name="ck_access_permission_name_length"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scope_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("access_scopes.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)


class ScopeGrantModel(Base):
    __tablename__ = "access_scope_grants"
    __table_args__ = (
        CheckConstraint(
            "subject_type IN ('user', 'group')", name="ck_access_scope_grant_subject"
        ),
    )

    subject_type: Mapped[str] = mapped_column(String(5), primary_key=True)
    subject_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_id: Mapped[str] = mapped_column(
        "scope_id",
        String(36),
        ForeignKey("access_scopes.id", ondelete="CASCADE"),
        primary_key=True,
    )


class PermissionGrantModel(Base):
    __tablename__ = "access_permission_grants"
    __table_args__ = (
        CheckConstraint(
            "subject_type IN ('user', 'group')",
            name="ck_access_permission_grant_subject",
        ),
    )

    subject_type: Mapped[str] = mapped_column(String(5), primary_key=True)
    subject_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_id: Mapped[str] = mapped_column(
        "permission_id",
        String(36),
        ForeignKey("access_permissions.id", ondelete="CASCADE"),
        primary_key=True,
    )
