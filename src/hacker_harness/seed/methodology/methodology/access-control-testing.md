# Access Control Testing for DRF

> Generic Django REST Framework access-control checklist for authorized engagements.
> Apply patterns via Hacker-Harness skills (`web-idor-bola-authorization`, auth-bypass playbooks).

## Example Finding Classes (Illustrative)

| Severity | Finding class | Typical endpoint shape |
|----------|---------------|------------------------|
| Critical | Cross-account write IDOR on resources | `PATCH /api/v1/resource/{id}/` |
| Critical | Resource transfer IDOR | `POST /api/v1/resource/{id}/transfer/` |
| High | Global config write/delete — no ownership | `PATCH /api/v1/config/{id}/` |
| High | Modify other users' webhooks / subscriptions | `PATCH /api/v1/event-subscription/{id}/` |
| Medium | OAuth token endpoint — JWT without credential check | `POST /api/v1/oauth/token/` |
| Medium | Exporter / integration credential leak | `GET /api/v1/exporter/` |
| Low | Global config readable (billing, feature flags) | `GET /api/v1/config/` |

## Surfaces Often Properly Scoped (Verify Per Target)

- `/api/v1/user/` — often queryset-scoped
- `/api/v1/organization/` — often queryset-scoped
- `/api/v1/purchase/` — often queryset-scoped
- `/api/v1/config/{key}/` — detail may be protected while list is not
- HEAD returning 200 on all endpoints — check method-level bypasses separately

## Schema Analysis Checklist

- Confirm OpenAPI / schema security requirements (no truly unauthenticated admin surfaces)
- Probe undocumented `/admin/`, `/legacy/`, `/internal/`, `/v2/` paths
- Flag internal-only endpoints that appear in schema but lack UI entry points

## Access Control Pattern (DRF Defaults)

Typical DRF auth model:
- **Authentication:** Session-based (`sessionid` cookie) + CSRF tokens, or JWT bearer
- **Authorization:** `get_queryset()` scopes reads, but `perform_update()` / `perform_destroy()` often skips re-checking ownership
- **Bulk actions:** Frequently skip per-item ownership validation
- **Config endpoints:** Sometimes no ownership model — any auth user can CRUD
- **OAuth:** `POST /api/v1/oauth/token/` may exchange a session for JWT without `client_credentials` verification

## Testing Methodology

1. Distill access-control patterns from IDOR / auth-bypass skills into a focused matrix
2. Load the matrix into Hacker-Harness context (avoid loading unrelated skills)
3. Run test categories against authenticated sessions for at least two roles / tenants
4. Promote confirmed issues to findings with request/response evidence

## Related

- [[methodology/drf-pentest-patterns|DRF Pentest Patterns]]
- [[methodology/cross-account-session-testing|Cross-Account Session Testing]]
