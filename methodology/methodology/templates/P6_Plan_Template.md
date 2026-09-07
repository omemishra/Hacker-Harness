# P6 Plan Template — Business Logic Testing
## Use for: Any target after P1-P5 complete
## Created by: Hacker-Harness — reads Map_Business.md + offensive-business-logic skill, writes plan for HH / spawn_agent execution
## Files the executor receives: this plan + API_Endpoint_With_Value.md + API_format.md + ps_tokens.txt

---

## Auth
- **Token file:** `scripts/ps_tokens.txt` (full non-truncated — do NOT truncate or abbreviate)
- **Required headers:** `{header name from P3 — exact case}` — use the exact casing (e.g., X-CSRF-Token, not XSRF-TOKEN)
- **ORGID/PROJID:** from tokens file or established during P1
- **Requests via:** `{proxy/MCP tool configured for this target}` — ALL requests must go through this. Direct curl will fail.

---

## Attack Pattern Reference

For each module in `Map_Business.md`, identify which patterns apply. Each pattern suggests specific test scenarios:

| # | Pattern | What to Test | Example Attack |
|---|---------|-------------|----------------|
| 1 | **State Machine Bypass** | Can the workflow state be moved backward, forward skipping steps, or while locked? | Approved → Draft, Draft → Issued (skip Review), unlock locked workflow |
| 2 | **Race Condition** | Can a one-shot action be triggered multiple times in parallel? | Send 2-5 parallel POST requests for approve/invite/redeem/reject |
| 3 | **Segregation of Duties** | Can the same user create and approve? Can a low-privilege role perform admin actions? | Creator approves own change order, Viewer invites new user |
| 4 | **Financial Abuse** | Can amounts be manipulated beyond business rules? | Negative/zero/overflow amounts, decimal precision abuse, currency swap |
| 5 | **Mass Assignment** | Does the endpoint accept extra fields beyond what the UI sends? | Add `{"isAdmin":true,"role":"admin","credits":99999}` to POST body |
| 6 | **Time Manipulation** | Can time-based restrictions be bypassed? | Set date to past (expired promo), future (premature access), replay expired token |
| 7 | **Cache/Persistence Bypass** | Can cache operations affect other users' data? | Write to cache with another user's ID, cache invalid IDs |
| 8 | **De-provisioning** | Can a removed user still access project data? | Remove user, fresh login, re-test — ~75% may still leak |

### Additional Categories to Consider (from the skill)
Not all apply to every target. Check each and mark ✅ applicable or ❌ N/A before writing the plan:

| Category | Check | Test Ideas |
|----------|-------|------------|
| Rate limiting / Anti-automation | ☐ | Is there any throttle on report generation, invites, or writes? Test 100 sequential requests |
| Multi-step chain attacks | ☐ | Can you combine two findings for higher impact? (e.g., create as Viewer → read as Owner) |
| Deletion abuse | ☐ | Can low-role delete records, files, or patterns they didn't create? |
| File upload logic | ☐ | Size limits, type restrictions, overwrite protection, path traversal |
| Notification manipulation | ☐ | Can you mark others' notifications as read, or spam invitations? |
| Subscription/tier/quota | ☐ | Can downgrade retain premium features? Can quota be refreshed mid-cycle? |
| Referral/reward loops | ☐ | Can you refer yourself multiple times? (fintech/gaming targets only) |

---

## Per-Module Test Cases

For each module from `Map_Business.md`, create a section following this structure:

### {Module Name 1 — from Map_Business.md}
**Business flow:** {Describe the end-to-end process — e.g., "A change order goes through Draft → Review → Approved → Issued. Once Issued, it should be locked and immutable."}
**API endpoints:** {List all endpoints — e.g., WorkflowSystem/UpdateWorkflowState, WorkflowSystem/ChangeWorkflowLock, WorkflowSystem/GetWorkflowSettings}
**Confirmed rules from P5:** {e.g., ❌ C1: Viewer can write to CacheRecordChange. ✅ GetMyNotifications: user-scoped. ❓ WorkflowSystem: 306 NRE on QA}
**Real values to use:** {Specific IDs — e.g., workflowId=1, projectId=2, UserID=274a3543-..., orgId=978ba72f-...}

| # | Attack Pattern | Test Scenario | Endpoint | Body / URL Params | Expected Result | If Wrong = Bug Type |
|---|---------------|--------------|----------|-------------------|-----------------|---------------------|
| 1 | State machine | {e.g., Modify workflow state as Viewer} | POST /api/{org}/{proj}/{Controller}/{Action} | {"stateName":"Approved","workflowId":1} | 306/403 (blocked) | State machine bypass |
| 2 | State machine | {e.g., Lock bypass} | POST /api/{org}/{proj}/{Controller}/{Action} | {"locked":false,"workflowId":1} | 306/403 (blocked) | Lock bypass |
| 3 | State machine | {e.g., Backward transition} | POST /api/{org}/{proj}/{Controller}/{Action} | {"stateName":"Draft","workflowId":1} | 306/403 (blocked) | State machine violated |
| 4 | Race condition | {e.g., Double-approve} | Same as #1, parallel 2x | Same body | First=200, Second=409 | No idempotency |
| 5 | Segregation | {e.g., Viewer changes locked workflow} | POST /api/{org}/{proj}/{Controller}/{Action} | {"locked":false,"workflowId":1} | 306/403 (blocked) | Segregation failure |
| 6 | Mass assignment | {e.g., Extra admin field} | POST /api/{org}/{proj}/{Controller}/{Action} | +{"isAdmin":true} | 306/403 (rejected) | Mass assignment |
| 7 | Time manipulation | {e.g., Past date} | POST /api/{org}/{proj}/{Controller}/{Action} | {"date":"2020-01-01"} | 400/306 (rejected) | Time bypass |

### {Module Name 2 — from Map_Business.md}
**Business flow:** {Describe...}
**API endpoints:** {List...}
**Confirmed rules:** {✅ / ❌ / ❓}
**Real values:** {Specific IDs...}

| # | Attack Pattern | Test Scenario | Endpoint | Body / URL Params | Expected Result | If Wrong |
|---|---------------|--------------|----------|-------------------|-----------------|----------|
| 1 | Segregation | {Specific test} | POST ... | {"field":"val"} | 306/403 | {Bug type} |
| 2 | Race condition | {Specific test} | Same, parallel 2x | Same body | 200/409 | Race condition |
| 3 | Mass assignment | {Specific test} | Same endpoint | +{"field":"val"} | 306/403 | Mass assignment |

### {Module Name 3}
...

---

## Output

### Business_Test_Out.md — Record EVERY test case result (pass or fail)

| # | Module | Attack Pattern | Test Scenario | Endpoint | Expected | Actual | Root Cause Analysis | Finding? | P7? |
|---|--------|---------------|--------------|----------|----------|--------|-------------------|----------|-----|
| 1 | Workflows | State machine | Downgrade Approved→Draft | POST /api/... | 306/403 | 200 | No auth check before state transition | ✅ C9 | Yes |
| 2 | Core Records | Cache bypass | Cache another user's record | POST /api/... | 306/403 | 200 | No auth on cache write (C1 confirmed) | ✅ C1 | Yes |
| 3 | Reports | Segregation | Viewer initiates report | POST /api/... | User-scoped | 200 | No user isolation check | ✅ H2 | Yes |
| 4 | Team Members | Segregation | Viewer invites user | POST /api/... | 306/403 | 306 NRE | Handler crashes before auth — needs prod test | ❓ Pending | - |
| 5 | User Settings | Segregation | Change another's preference | POST /api/... | 306/403 | 200 | No cross-user check | ✅ H8 | No |

**Column explanations:**
- **Expected:** What should happen per the business rule (306 = auth failure, 200 = success, 409 = race blocked)
- **Actual:** What actually happened (200, 306, 403, 404, 500, etc.)
- **Root Cause:** Why actual differed from expected — e.g., "No auth check", "No validation", "No idempotency key", "306 NRE on QA"
- **Finding?:** ✅ = bug confirmed (add to Business_find.md), ❌ = passed (no bug), ❓ = inconclusive (needs prod test)
- **P7?:** Yes = add to P7_Plan.md for cross-account testing

### Business_find.md — Only findings (where actual ≠ expected)

For each confirmed finding (✅ in Business_Test_Out.md), create an entry:

```markdown
### {Finding ID}: {Bug Name}
- **Module:** {Module name}
- **Attack Pattern:** {State machine / Race / Segregation / Financial / Mass assignment / Time / Cache}
- **Endpoint:** {Full URL with all parameters — clickable if possible}
- **HTTP Method:** {POST / GET / PUT / PATCH / DELETE}
- **Auth Used:** {low-privilege role or admin role}
- **Body / Parameters:** {Complete request body or URL params}
- **Expected Behavior:** {What the business rule requires — e.g., "Only Owners should approve change orders"}
- **Actual Behavior:** {What happened — e.g., "low-privilege role received HTTP 200 and the workflow transitioned"}
- **Root Cause:** {Why the rule was broken — e.g., "No authorization check on UpdateWorkflowState"}
- **Impact:** {What an attacker can achieve — e.g., "Approve own change order for financial gain"}
- **P7 Applicable:** Yes / No — if Yes, tested cross-account in P7
```

### Cross-Account Flagging for P7

After completing all tests, review Business_Test_Out.md for entries where P7? = Yes:

1. For each flagged entry, copy to `P7_Plan.md` under a "Business Logic Cross-Account Tests" section
2. Include the same test scenario, endpoint, body, and expected result
3. The P7 agent will re-execute using Tenant B's tokens instead of Tenant A's
4. If the bypass also works cross-account → critical cross-tenant vulnerability

**Common P7 candidates:**
- Any finding where root cause is "No auth check" — auth is missing entirely, likely also missing cross-account
- Any finding where root cause is "No validation" — validation is missing, likely also missing cross-account
- Findings marked ❓ (306 NRE on QA) — may work on prod with correct values

---

## Execution Instructions

**What the executor receives:**
- `P6_Plan.md` (this file — test cases to execute, specific endpoints, bodies, expected results)
- `API_Endpoint_With_Value.md` — real IDs and values to substitute into {placeholder} fields
- `API_format.md` — working body formats for each endpoint (field names, types, nesting structure)
- `ps_tokens.txt` — full auth tokens for both low-privilege and admin roles

**Executor does NOT receive:** Map_Business.md, appsummary.md, skill files, prior findings — only the plan and the data it needs to construct requests.

**Step-by-step execution flow for each test case:**

1. Read the test case row from the plan — identify the endpoint, method, body, and expected result
2. Look up the real values from API_Endpoint_With_Value.md — replace `{org}`, `{proj}`, `{id}`, `{userId}` with actual values
3. Look up the body format from API_format.md if the plan's body is a summary
4. Construct the complete HTTP request with full headers (including auth tokens in raw HTTP)
5. Send the request as **low-privilege role** using the configured proxy/MCP tool
6. Record the HTTP status code and response body
7. **If 200 (bypass):** Send the SAME request as **admin role** to confirm the endpoint works — this rules out "endpoint is broken" vs "endpoint has no auth"
8. Record both results in Business_Test_Out.md
9. If actual result differs from expected → this is a potential finding → add to Business_find.md
10. If root cause is missing auth → flag P7? = Yes

**Special cases:**

- **Race condition tests:** Send 2-5 requests in rapid parallel (not sequential). Record the response status of EACH request. If all return 200 → race condition confirmed (no idempotency). If second returns 409/306 → idempotency working.
- **Mass assignment tests:** Add ONE extra field at a time (isAdmin, role, credits, balance, permissions). Do NOT add all at once — you won't know which was accepted. Verify by reading the record back via GET if possible.
- **306 NRE (Null Reference Exception):** The handler crashed before auth check. This may work on production if valid input values are provided. Mark as ❓ and note for prod testing.
- **404 endpoints:** If an endpoint returns 404, skip it and note "Controller not deployed on this environment." Do NOT waste tokens retrying.
- **Rate limiting:** If you get rate-limited, wait 30s and retry once. If blocked again, note it and move to next test.
