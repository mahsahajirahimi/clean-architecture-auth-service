# Central Authentication & Authorization Service

Architecture-only starting point for a university assignment: a simplified, single-realm identity provider and authorization service.

**Status: design only.** This commit intentionally contains **no Python code, executable entry points, package dependencies, database migrations, implementation, or tests**. The empty source/test directories contain `.gitkeep` files so Git can track the intended structure.

## Architecture

- **Deployment:** one deployable application (Modular Monolith), not multiple networked microservices.
- **Internal design:** Clean Architecture with inward-pointing source-code dependencies.
- **Modules:** `identity` (users, groups, memberships, authentication) and `access_control` (scopes, permissions, grants, access checks).
- **Interfaces:** HTTP API planned; no front-end required.
- **Persistence:** one database initially; logical data ownership per module.
- **Security:** password hashing and token-based authentication planned; authorization decisions must reflect current membership and grants.

## Documentation

- [Architecture and dependency boundaries](docs/architecture.md)
- [Proposed domain model](docs/domain-model.md)
- [Planned API capabilities](docs/api-contracts.md)
- [ADR-0001: Modular Monolith + Clean Architecture](docs/adr/0001-modular-monolith-clean-architecture.md)

## Planned directory layout

```text
src/auth_service/
  composition/                 # Composition root / dependency injection (planned)
  modules/
    identity/
      domain/                  # Business entities and invariants
      application/             # Use cases and ports
      infrastructure/          # Repository/crypto/token adapters
      presentation/            # HTTP endpoints and schemas
    access_control/
      domain/                  # Permissions and authorization rules
      application/             # Access-control use cases and ports
      infrastructure/          # Persistence and external adapters
      presentation/            # HTTP endpoints and schemas
tests/
  unit/
  integration/
```

Only directories and documentation have been committed at this stage. Future implementation should conform to the documented boundaries.
