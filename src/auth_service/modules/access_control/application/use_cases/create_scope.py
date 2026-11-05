from uuid import uuid4

from auth_service.modules.access_control.application.exceptions import (
    DuplicateScopeError,
)
from auth_service.modules.access_control.application.ports import ScopeRepository
from auth_service.modules.access_control.application.use_cases._validation import (
    normalize_name,
)
from auth_service.modules.access_control.domain.entities.scope import Scope


class CreateScope:
    def __init__(self, scopes: ScopeRepository):
        self.scopes = scopes

    def execute(self, name: str) -> Scope:
        name = normalize_name(name, "Scope name")
        if self.scopes.get_by_name(name) is not None:
            raise DuplicateScopeError("Scope name already exists")
        scope = Scope(uuid4(), name)
        self.scopes.save(scope)
        return scope
