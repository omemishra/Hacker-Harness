# P7 Plan Template — Cross-Account / Cross-Tenant Testing
## Use for: Any target with multi-tenant, multi-organization, or multi-workspace architecture
## Generated from: 100% of live endpoints in `API_Endpoint_With_Value.md` and business findings in `Business_Test_Out.md`

---

## 🚨 Traffic & Proxy Rules
- **Primary:** Issue all test requests via Caido MCP (`caido_send_request` via `mcp__caido__caido_send_request`).
- **Secondary:** If running automated scripts, route through the local proxy: `curl -x http://127.0.0.1:8080 -k`.
- **Fallback ONLY:** Direct unproxied `curl` only if Caido is unreachable or explicitly disabled.

---

## Auth & Target Parameters
- **Tenant A (Target Org / Victim):** `{TENANT_A_ID}`, `{PROJECT_A_ID}`, `{RESOURCE_A_ID}`
- **Tenant B (External User / Attacker):** `{TENANT_B_ID}`, Active Session Cookie / Token B, Anti-CSRF Token B
- **Token file:** `ps_tokens.txt`

---

## Plan Creation Checklist (DO NOT SKIP)
Before writing this plan, read all of the following artifacts:
1. ❐ `Business_Test_Out.md` — P6 findings flagged as candidates for cross-tenant replication.
2. ❐ `API_Endpoint_With_Value.md` — 100% of discovered live endpoints (every endpoint must be tested cross-tenant).
3. ❐ `API_format.md` — Body schemas for write operations (POST/PUT/PATCH).
4. ❐ `phase1_enumeration.md` — Verified live actions and baseline response structures.

---

## Cross-Tenant Test Categories

### 1. Cross-Tenant IDOR / BOLA on Discovered GET Endpoints
Test EVERY live GET endpoint with Tenant A's object and path identifiers while injecting Tenant B's credentials:

| Domain / Resource | Endpoint | Expected (Cross-Tenant) | If Vulnerable |
|---|---|---|---|
| {Domain 1} | `GET /api/{TENANT_A_ID}/{resource}` | 403 / 401 / Empty List | Cross-Tenant Data Leak |
| {Domain 2} | `GET /api/{resource}?orgId={TENANT_A_ID}` | 403 / 401 / Empty List | Query-Param BOLA Bypass |

### 2. Cross-Tenant Mutation & BFLA (POST / PUT / PATCH / DELETE)
Test state-changing endpoints targeting Tenant A's resources using Tenant B's credentials:

| Finding / Action | Endpoint | Expected (Cross-Tenant) | If Vulnerable |
|---|---|---|---|
| {Action 1} | `POST /api/{TENANT_A_ID}/{resource}` | 403 / 401 / Blocked | Cross-Tenant Write BFLA |
| {Action 2} | `DELETE /api/{resource}/{RESOURCE_A_ID}` | 403 / 401 / Blocked | Cross-Tenant Object Deletion |

### 3. Cross-Tenant Data Aggregation / Nil-Identifier Testing
Test default/null scoping identifiers across tenant contexts:

| Test | Endpoint | Expected | If Vulnerable |
|---|---|---|---|
| Default Tenant Scope | `GET /api/00000000-0000-0000-0000-000000000000/{resource}` | Filtered to Tenant B only | Global Data Aggregation Leak |

---

## Output Deliverables
- `GenPentest/plans/P7_Plan.md` — Concrete cross-tenant test plan.
- `GenPentest/cross_account_with_value.md` — Discovered parameters and cross-tenant objects.
- `GenPentest/findings/cs_crossaccount.md` — Detailed finding reports with full reproduction payloads.
- Update master ledger: `GenPentest/Vulnerabilities.md`.
