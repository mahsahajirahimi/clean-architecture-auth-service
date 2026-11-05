from sqlalchemy import Engine

from auth_service.infrastructure.persistence.database import Base
from auth_service.modules.access_control.infrastructure.persistence.models import (
    PermissionGrantModel,
    PermissionModel,
    ScopeGrantModel,
    ScopeModel,
)
from auth_service.modules.identity.infrastructure.persistence.models import (
    AdministratorModel,
    GroupMembershipModel,
    GroupModel,
    UserModel,
)


def create_schema(engine: Engine) -> None:
    """Register and create both modules' tables without relying on incidental imports."""
    Base.metadata.create_all(
        engine,
        tables=[
            UserModel.__table__,
            GroupModel.__table__,
            GroupMembershipModel.__table__,
            AdministratorModel.__table__,
            ScopeModel.__table__,
            PermissionModel.__table__,
            ScopeGrantModel.__table__,
            PermissionGrantModel.__table__,
        ],
    )
