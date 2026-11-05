from auth_service.modules.access_control.application.ports import ScopeRepository
from auth_service.modules.access_control.application.use_cases._validation import (
    validate_pagination,
)
from auth_service.modules.access_control.domain.entities.scope import Scope


class ListScopes:
    def __init__(self, scopes: ScopeRepository):
        self.scopes = scopes

    def execute(self, limit: int = 50, offset: int = 0) -> list[Scope]:
        validate_pagination(limit, offset)
        return self.scopes.list(limit, offset)
