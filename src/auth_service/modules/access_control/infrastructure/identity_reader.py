from uuid import UUID

from auth_service.modules.access_control.application.dto import UserAccessContext
from auth_service.modules.identity.application.access_queries import (
    IdentityAccessQueries,
)


class IdentityReaderAdapter:
    def __init__(self, queries: IdentityAccessQueries):
        self.queries = queries

    def get_user_context(self, user_id: UUID) -> UserAccessContext | None:
        context = self.queries.get_user_context(user_id)
        if context is None:
            return None
        return UserAccessContext(context.user_id, context.is_active, context.group_ids)

    def group_exists(self, group_id: UUID) -> bool:
        return self.queries.group_exists(group_id)
