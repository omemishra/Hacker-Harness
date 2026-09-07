---
name: web-idor-bola-authorization
description: Insecure Direct Object References (IDOR) & Broken Object Level Authorization (BOLA), UUID/numeric ID tampering, HTTP method swaps, array wrapping, and multi-tenant access control testing.
playbook: web-security
pivots_to:
  - web-api-mass-assignment-pollution
  - genpentest-p7-cross-org
  - genpentest-p5-role-matrix
---

# Web IDOR & Broken Object Level Authorization (BOLA)

## Attack Vector Summary
Insecure Direct Object References (IDOR / BOLA) occur when an API endpoint takes user-supplied object identifiers (e.g., `user_id`, `account_id`, `document_uuid`, `order_id`) to retrieve, modify, or delete backend records without validating that the authenticated user possesses authorization for that specific entity.

## Tactical Heuristics & Step-by-Step Flow

### 1. Identifier Mining & Classification
Extract object identifiers across all endpoints in `APIendpoint.md`:
- **Numeric sequential IDs:** `id=1024`, `order_id=5821` (Test incremental $+1, -1$ and random sampling).
- **UUIDs / GUIDs:** `id=274a3543-7ec9-467a-8b87-43cfce84a0d8` (Collect valid IDs from multiple test accounts/tenants; never guess UUIDs).
- **Encoded Identifiers:** Base64, hex, or hashes of emails (`id=dGVzdEBleGFtcGxlLmNvbQ==`).

### 2. Multi-Role & Cross-Account Auth-Swap Matrix
Always test with two distinct accounts ($User_A$ and $User_B$):

```http
# Step 1: User A creates or accesses their own resource
GET /api/v1/documents/DOC_ID_USER_A HTTP/1.1
Host: target.com
Authorization: Bearer TOKEN_USER_A

# Response 200 OK with User A data.

# Step 2: User B sends request targeting User A's DOC_ID
GET /api/v1/documents/DOC_ID_USER_A HTTP/1.1
Host: target.com
Authorization: Bearer TOKEN_USER_B

# Vulnerable Marker: HTTP 200 OK returning User A document to User B.
```

### 3. Mutation & Method Swapping Techniques
If `GET` is protected, test all state-changing HTTP methods on the foreign object ID:
- `PUT /api/v1/users/{FOREIGN_ID}` or `PATCH /api/v1/users/{FOREIGN_ID}`
- `DELETE /api/v1/documents/{FOREIGN_ID}`
- `POST /api/v1/projects/{FOREIGN_ID}/members`

### 4. Parameter Mutation Bypass Vectors
- **Array Wrapping:** `{"id": [FOREIGN_ID]}` or `{"id": {"id": FOREIGN_ID}}`
- **JSON Field Duplication / HPP:** `?id=MY_ID&id=FOREIGN_ID`
- **Path Traversal in IDs:** `/api/v1/users/MY_ID/../FOREIGN_ID`
- **API Version Downgrade:** Test `/api/v1/` vs `/api/v2/` vs `/api/v3/` or `/internal/`.

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| Cross-Tenant Read IDOR | API queries by ID without `tenant_id` filter | `GET /api/invoices/1042` with Org B session | 200 OK returning Org A financial invoice |
| State-Changing Write IDOR | `PATCH /profile/{id}` fails to check session ownership | `PATCH /api/users/205` body `{"email":"attacker@evil.com"}` | Target user email changed; ATO achieved |
| IDOR on Delete Action | `DELETE /items/{id}` allows cross-user resource wipe | `DELETE /api/projects/3` with viewer token | Resource deleted without proper permission |
| GraphQL Node Resolver IDOR | `node(id: "...")` resolver lacks authorization | `query { node(id: "VXNlcjoxMDI=") { ... on User { email } } }` | Private user object returned across tenants |

## Evidence Collection & Validation Gate
- Capture side-by-side HTTP logs showing $User_A$'s ID accessed by $User_B$'s session token.
- Prove actual state mutation or private data exposure.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
