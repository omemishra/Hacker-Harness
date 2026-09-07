# P5 Plan Template — Same-Account Role Matrix (Phase-Gated)
## Use for: Any target application or API with multiple user roles (Admin / Manager / Member / Viewer / Guest)
## Generated from: 100% of discovered endpoints in P3 `APIendpoint.md`

---

## 🚨 Traffic & Proxy Rules
- **Primary:** All test requests MUST use Caido MCP (`caido_send_request` via `mcp__caido__caido_send_request`) so every request and response is cataloged in proxy history.
- **Secondary:** If running automated terminal scripts, route through the local proxy: `curl -x http://127.0.0.1:8080 -k`.
- **Fallback ONLY:** Direct unproxied `curl` only if Caido is unreachable or explicitly disabled.

---

## Auth & Target Parameters (Extract dynamically from P0/P1)
- **Token file:** `ps_tokens.txt` (Full non-truncated cookies/tokens for all registered roles)
- **Anti-CSRF / Header:** Dynamic from P0/P1 (e.g. `X-CSRF-Token`, `X-XSRF-Token`, or target-specific custom header)
- **Target Identifiers:** `TARGET_HOST`, `TENANT_ID` / `ORG_ID`, `PROJECT_ID` / `WORKSPACE_ID`

---

## URL Routing Schemes (Test ALL variants before declaring an endpoint 404)
1. **Path-Scoped:** `https://{TARGET_HOST}/api/{TENANT_ID}/{PROJECT_ID}/{Controller}/{Action}`
2. **Query-Scoped:** `https://{TARGET_HOST}/api/{Controller}/{Action}?tenantId={TENANT_ID}&projectId={PROJECT_ID}`
3. **Root / App-Scoped:** `https://{TARGET_HOST}/api/{Controller}/{Action}` or `https://{TARGET_HOST}/api/{resource}`
4. **Default / Nil-Identifier Scoped:** `https://{TARGET_HOST}/api/00000000-0000-0000-0000-000000000000/0/{Controller}/{Action}`
5. **Header-Scoped:** Requesting `https://{TARGET_HOST}/api/{resource}` with `X-Tenant-ID: {TENANT_ID}`

---

## Mutation & BFLA/IDOR Testing Rules (Phase 3)

### Step-by-Step Flow
```text
1. GET Baseline & Schema Discovery:
   → Query corresponding GET endpoint first to observe property names and body schemas.
   → Extract live identifiers (e.g., entity IDs, UUIDs, email addresses) for mutation testing.

2. Initial Probe with Candidate Body:
   → Transmit candidate body derived from GET schema or API discovery.

3. Dynamic Error-Feedback Loop:
   → 400 / 422 "Field X is required" → ADD field X with valid test value, keep existing fields.
   → 500 DB / SQL error naming a column → USE that column name as a JSON body key.
   → Framework / Null-Ref Exception → Try alternative nesting (flat vs nested payload).
   → Anti-Pattern in Body (HTTP 200 with {"error": "Unauthorized"}) → Attempt path/parameter variants.

4. Multi-Domain IDOR / BOLA Probing:
   → Swap entity IDs / project IDs / tenant IDs across multiple distinct functional areas (Records, Documents, User Profiles, Settings, Reports).
   → NEVER declare "No IDOR" from testing only 1 endpoint.

5. Role Hierarchy Evaluation:
   → Test as Lowest-Privilege Role first (Viewer / Member) → if 200 with write/data = BFLA / Privilege Escalation.
   → Test as Highest-Privilege Role (Admin / Owner) to verify the endpoint is functional.
   → Test as Anonymous (Unauthenticated) → 200 with data = CRITICAL Authentication Bypass.
```

## Status Code Interpretation
| Response | Meaning | Next Step |
|----------|---------|-----------|
| 200 with data | Endpoint works | Check if lower role should have access |
| 200 with "Unauthorized" in body | Anti-pattern | Auth in body, not status — bypassable? |
| 306 `{"message":"Unauthorized"}` | Auth gate | Session valid, insufficient perms |
| 306 `{"message":"Object reference not set..."}` | NRE before auth | **No auth check ran** — privesc potential |
| 404 (IIS HTML) | Controller not deployed | Note, skip |
| 404 (JSON) | Route not registered | Try alternative path |
| 405 with Allow: POST | Wrong method | Use correct method |
| 401/403 | Framework auth | Rare — most apps don't have [Authorize] |

## Anon Response Interpretation
| Response | Meaning |
|----------|---------|
| 302 → login | ✅ Properly blocked |
| 401 Unauthorized | ✅ Auth required |
| 200 with data | ❌ **AUTH BYPASS — P1** |
| 306 | Auth gate ran (anonymous detected) |

## Classification by Permission
| Response | Role A | Role B | Interpretation |
|----------|--------|--------|----------------|
| 200 | ✅ Admin | ❌ 403 | Proper isolation |
| 200 | ✅ User | ❌ 403 | Proper isolation |
| 200 | ✅ User | ✅ User B | Horizontal IDOR |
| 200 | ✅ User | ✅ Admin | BFLA — P1 |
| 403 | ❌ Both | ❌ Both | Role required (but which?) |
| 401 | ❌ Both | ❌ Both | Auth required |
| 200 | ✅ Both | ✅ Both | Public endpoint |

## Privilege Escalation via Mass Assignment
```
POST /api/user/register
  {"name": "test", "role": "admin"}           → role field in body
  {"name": "test", "is_admin": true}           → boolean flag
  {"name": "test", "permissions": ["*"]}       → wildcard permissions
  {"name": "test", "group": "administrators"}  → group escalation
```

## Method Tampering
```
GET  /api/user/1    → 200 (normal read)
POST /api/user/1    → 200? Creating instead of reading
PUT  /api/user/1    → 200? Updating
PATCH /api/user/1   → 200? Partial update with role change
```

## Detailed Auth Matrix Test Cases
| Category | Test | Owner Expect | Viewer Expect | Result |
|----------|------|-------------|---------------|--------|
| Settings | Modify tenant config | 200 | 306 | |
| User Mgmt | Invite user | 200 | 306 | |
| User Mgmt | Change role (Viewer→Owner) | 200 | 306 | |
| CRUD | Create resource | 200 | 306 | |
| CRUD | Edit resource | 200 | 306 | |
| CRUD | Delete resource | 200 | 306 | |
| Read | View data | 200 | 200 | Expected |
| Session | Role change effect | Immediate | N/A | |

## Controller to Endpoint Table (generated from APIendpoint.md)
| Controller | Action | Method | Designed For (from JS) | Try Body | Mutation Strategy |
|------------|--------|--------|----------------------|----------|-------------------|
| {ctrl} | {action} | {method} | Admin/All/? | {params from P3} | Try flat, with query params, etc. |
| ... | ... | ... | ... | ... | ... |

## Permutation Testing (using API_Endpoint_With_Value.md values)
| Test | Method | Expect | Finding if wrong |
|------|--------|--------|-----------------|
| Own data | Any | 200 | — |
| Cross-entity (other's ID/project) | Any | 306 | IDOR |
| Escalate role | POST/PUT/PATCH | 306 | Privesc |
| Extra fields (+is_admin) | POST/PUT/PATCH | Rejected | Mass assignment |
| Response contains PII | Any | No | Info disclosure |
| No auth (anon) | Any | 302 | Auth bypass |

## Agent Architecture — Phase-Gated with File Handoff
```
P5_Plan.md
     ↓
Agent 1 — Phase 1 + 2 (1 agent, sequential)
  → Enumeration: all endpoints with all roles + anon
  → Discovery: GET as most privileged role (Admin), extract real values
     Maps P3 field names to GET response fields
  → Writes: phase1_enumeration.md, API_Endpoint_With_Value.md, API_Value_Waited.md
  → Killed. Next agents start fresh from disk.
     ↓
Agents 2-5 — Phase 3 (3-4 agents PARALLEL, ~12 controllers each via spawn_agent)
  → Read: API_Endpoint_With_Value.md (values from Phase 2)
  → All methods (GET/POST/PUT/PATCH) → error → mutate → retry → permute
  → Check API_Value_Waited.md as new values found → retry waited endpoints
  → Each writes: a0_findings.md, a1_findings.md, a2_findings.md, a3_findings.md
  → All killed. A0 starts fresh from disk.
     ↓
A0 — Phase 4 (consolidation)
  → Reads all findings files
  → Writes: cs_roles.md, API_format.md, API_Endpoint_With_Value.md (final),
             API_Value_Waited.md (remaining gaps), Vulnerabilities.md
  → Handoff to P6

**Role Mutation Testing (P5 Enhancement):** After parallel agents, run sequential role mutation.
Key: **only test restrictions** — what the role SHOULD NOT be able to do. Expected behavior = wasted tokens.

**Prerequisite — `user_permission.md`:** During P1 and P3, discover and document:
- Role management endpoints (`admin/users`, `admin/roles`, etc.)
- Available roles and their permissions
- What each role CAN vs CANNOT do
- Custom role functionality if exists
- Save to `~/Targets/<domain>/user_permission.md`
- This file drives P5 role mutation testing

**Execution:**
1. Read `user_permission.md` — understand all roles and boundaries
2. Create accounts: `tester+{app}{random}@example.com`
3. Start lowest role → test ALL endpoints → record baseline (allowed vs blocked)
4. Change user role to next level → test ONLY what SHOULD still be blocked
5. Test WITHOUT re-login → then re-login and compare
6. For downgrade tests: verify old capabilities are now blocked
7. If custom roles: create → set restrictions → test enforced → modify → re-test
8. Catches: cached auth, no-reauth updates, downgrade not enforced, restrictions not enforced
```

## APIendpoint.md → P5 Mutation Loop → API_format.md Pipeline
```
P3 (JS analysis) → APIendpoint.md (field names + nesting + Designed For)
     ↓
P5 Phase 1 → Try format from APIendpoint.md as INITIAL GUESS
     ↓
P5 Mutation → If error, refine based on response:
            → 400 "field X required" → ADD field X, retry
            → 500 SQL column name   → USE column as key, retry
            → 306 NullRef           → Try different nesting/flattening
     ↓
P5 Phase 4 → Save WORKING format to API_format.md
             Save FORMAT + VALUES to API_Endpoint_With_Value.md
     ↓
P6          → Load API_Endpoint_With_Value.md (no rediscovery)
             → Load API_Value_Waited.md (check if P6 has missing values)
```

## Phase 2: GET as Most Privileged Role (Admin) — Extract Values
```
P3 says field names:       contactid, userpk, email
GET as ADMIN → /getTeamMembersForInvite/
  → returns: {"UserID":"abc123","Email":"user@test.com"}
  MAP: P3 "userpk" = GET "UserID" = "abc123"
  MAP: P3 "email" = GET "Email" = "user@test.com"
  SAVE to API_Endpoint_With_Value.md

Phase 3 privesc test:
  POST as VIEWER with body: {"userpk":"abc123","email":"user@test.com"}
  → If 200 = privesc (Viewer used Admin's data)
  → If 306 = blocked (expected)
```

## Phase 3: Common Body Formats by Endpoint Type
```json
// User management
{"userId":"<RealGUID>","role":"Owner","projectId":2}
{"email":"test@test.com","firstName":"POC","role":"Viewer"}

// Workflow/status
{"workflowId":<CollectionKey>,"locked":false}
{"templateId":0,"name":"poc_test","tableType":49}

// Document management
{"folderName":"poc_test","parentFolderId":0}
{"componentId":1,"revisionNumber":"1"}

// Record CRUD
{"recordId":<RealId>,"fieldName":"Name","fieldValue":"poc"}
{"ids":[<RealId>]}
```

## Controller Deployment Status
| Status | Count | Controllers |
|--------|-------|-------------|
| ✅ LIVE (200 responses) | N | (list) |
| ⚠️ NEEDS VALID INPUT (306 POST) | N | (list) |
| ❌ NOT DEPLOYED (404) | N | (list) |

## Output Files
| File | Contents | When Created | Used By |
|------|----------|-------------|---------|
| `phase1_enumeration.md` | Raw status matrix (all endpoints × roles) | Phase 1 | Phase 2 |
| `API_Endpoint_With_Value.md` | Real values + working request formats | Phase 2 → 4 | P5 + P6 |
| `API_Value_Waited.md` | Endpoints with missing values | Phase 2 → 4 | P5 + P6 |
| `cs_roles.md` | All findings per endpoint × role | Phase 4 | Report |
| `API_format.md` | Working body formats (field names only) | Phase 4 | P6 reference |
| `Vulnerabilities.md` | Consolidated findings with severity | Phase 4 | Report |
