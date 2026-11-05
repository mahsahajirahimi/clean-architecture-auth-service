# Final review — practical assignment

Review date: 2026-11-05. Scope: the practical authentication/authorization service
and its minimal local dashboard. The existing changes from the preceding API step
are retained; this review does not commit or push anything.

## Requirements and evidence

| Requirement | Implementation | Verification |
| --- | --- | --- |
| Central authentication, one realm | `/auth/login`, JWT validation, `/auth/me`; no tenant/realm selector | Authentication API and JWT integration tests |
| Users and groups | Create/list/get users and groups; active status management | Identity API, application, and persistence tests |
| Membership in several groups and moving between groups | Add/remove memberships; read both user groups and group members | Identity management tests and review read-endpoint tests |
| Scope and Permission | Scoped operations, unique catalog names, SQLAlchemy persistence | Domain, application, persistence, and API tests |
| Assign/revoke Scope or Permission for users/groups | Typed Grant with all four subject/target combinations | Access Control API tests and FK/unique-constraint tests |
| Effective access from direct and group grants | Additive union; scope grants cover current/future operations | Domain policy tests and complete HTTP scenarios |
| Changes affect subsequent decisions | Fresh status/membership/grants read through Identity Application contracts | Membership removal, revocation, inactivity, and same-token HTTP tests |
| Other systems can consume the service | Bearer-authenticated JSON APIs, OpenAPI at `/docs` | API tests through real adapters and temporary SQLite |
| Own implementation | FastAPI, SQLAlchemy, Argon2id, PyJWT; no packaged identity provider | Source/dependency review; `pip check` |
| Architecture and library justification | Modular Monolith, inward dependencies, module-owned data, composition root | Automated architecture checks and README |
| Minimal optional dashboard | Same-origin HTML/CSS/JavaScript at `/ui/` | Browser QA with a separate temporary database; HTTP/static-asset tests |

## Findings corrected

- Added protected, paginated reads for user groups and group members. Membership
  writes previously existed, but their current state could not be inspected by API.
- Added a protected, paginated list of a subject's direct grants across both target
  tables. Effective permissions alone do not identify which grant can be revoked.
- Identity entities now reject non-string names/hashes with validation errors.
- JWT date overflows now become invalid-token errors, rather than server errors.
- Added architecture regression checks: inner layers have no framework/storage
  imports, Access Control does not import Identity storage/domain, and repositories
  do not commit or roll back.
- Dashboard dynamic values use text nodes, tokens stay in memory, logout clears
  previous data, expired-session responses cannot refill a logged-out view, and
  forms fall back to POST if JavaScript is unavailable. Assets are local and are
  served with a restrictive CSP. API authorization remains server-side.

## Database decision

Keep explicit, idempotent schema initialization for this initial SQLite schema.
Tests verify adding the Access Control tables to an existing Identity database
without losing Identity data. `create_all` does not migrate changed columns;
introduce versioned migrations before the first change to an existing table's
shape. There is no schema alteration requiring Alembic in this review.

## Verification

The full suite passed 224 tests on Python 3.12. JavaScript syntax, dependency
consistency, layer boundaries, asset packaging, and real browser interaction
were also checked. The assembled wheel serves the dashboard and preserves
API authentication when executed from its extracted package. Browser QA uses
a separate temporary database: login, user/group/catalog creation, memberships,
group grants, positive/negative decisions, grant removal, logout/relogin, and the
ordinary-user view. Current project users/passwords are not replaced or reset.

## Remaining delivery work and limits

The formal university report still needs to be written and reviewed by the student;
README and this matrix provide its implementation evidence. This is the assignment's
custom single-realm API, without full OAuth2/OIDC/SSO, refresh tokens, persistent
JWT revocation, login throttling, multi-administrator recovery, or Internet hosting.
The initial administrator is bootstrapped locally. Dashboard logout clears its
in-memory token; an issued JWT remains valid until expiry unless the user becomes
inactive or the signing key changes. These boundaries are documented, not claimed
as implemented production identity-provider features.
