from sqlalchemy import Boolean, CheckConstraint, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from auth_service.infrastructure.persistence.database import Base


class UserModel(Base):
    __tablename__ = "identity_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class GroupModel(Base):
    __tablename__ = "identity_groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)


class GroupMembershipModel(Base):
    __tablename__ = "identity_group_memberships"

    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identity_users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    group_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identity_groups.id", ondelete="CASCADE"),
        primary_key=True,
    )


class AdministratorModel(Base):
    __tablename__ = "identity_administrator"
    __table_args__ = (CheckConstraint("id = 1", name="ck_identity_administrator_singleton"),)

    # The only possible primary key is 1, so concurrent bootstraps cannot both win.
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("identity_users.id", ondelete="RESTRICT"),
        unique=True, nullable=False,
    )
