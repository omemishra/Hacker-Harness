---
name: report-writing-triage
description: Authoritative, impact-first bug bounty and pentest report writing for HackerOne, Bugcrowd, Intigriti, Immunefi, YesWeHack, and executive HTML. Enforces title formulas, reproduction steps with copy-paste HTTP, CVSS 3.1 & 4.0 vectors, downgrade counters, and strict non-theoretical language.
playbook: reporting-triage
pivots_to: []
---

# Report Writing & Triage: Impact-First Vulnerability Reporting

## 1. The Core Principle: Zero Theoretical Language

> **Never use:** "could potentially", "could be used to", "may allow", "might be possible", "appears to", "seems to".
> **Always prove:** State exact data, exact access, and exact actions verified on live infrastructure.

```text
BAD:  "This vulnerability could potentially allow an attacker to access user data."
GOOD: "An unauthorized attacker can access any customer's invoice data and PII by substituting the `invoice_id` parameter. Confirmed via differential replay: attacker session successfully retrieved customer ID 456's billing address, tax ID, and transaction history."
```

---

## 2. Title Formula

Always construct titles using the standard formula:
```text
[Bug Class] in [Exact Endpoint / Feature] allows [Attacker Role] to [Impact] [Victim Scope]
```

**Publication-Grade Examples:**
- `SQL Injection Authentication Bypass in /Login.asp allows unauthenticated attacker to take over administrator accounts`
- `Local File Inclusion in /Templatize.asp allows unauthenticated attacker to disclose database credentials in db.asp`
- `Broken Object Level Authorization in /api/v1/orders/{id} allows authenticated user to read all tenant invoices`
- `Stored Cross-Site Scripting in Forum Post Body executes in viewer sessions to hijack session cookies`
- `Server-Side Request Forgery via /api/fetch-url reaches AWS IMDSv2 to exfiltrate IAM role credentials`

---

## 3. Platform-Specific Report Architectures

### 1. HackerOne Format
- **Summary:** Single impact-first paragraph: what the bug is, exact endpoint, method, parameter, exposed data, required privilege level.
- **Vulnerability Details:** Bug Class, Affected Endpoint, CVSS 3.1 Score + Vector (`CVSS:3.1/AV:N/AC:L/...`), CVSS 4.0 Vector.
- **Steps to Reproduce:**
  - Setup: Attacker account (role/ID) vs Victim account (role/ID).
  - Exact copy-pasteable HTTP request (with headers).
  - Exact server response demonstrating unauthorized data or state change.
- **Impact:** Quantified business and security impact (data volume, user count, regulatory scope like GDPR/CCPA).
- **Recommended Fix:** 1–2 sentence concrete code/architecture fix.

### 2. Bugcrowd Format (VRT-Aligned)
- **Title:** `[VRT Category] > [Subcategory] > P[1-4]: [Exact Impact in Endpoint]`
- **Description:** Impact-first summary paragraph.
- **Steps to Reproduce:** Exact numbered steps with raw HTTP requests and responses.
- **Expected vs Actual Behavior:**
  - *Expected:* `HTTP 403 Forbidden` / Parameterized query / Entity-encoded HTML.
  - *Actual:* `HTTP 200 OK` exposing private victim data / SQL execution.
- **Severity Justification:** Reference Bugcrowd VRT priority (P1–P4) with justification (no user interaction, mass exposure).
- **Remediation:** Direct code fix guidance.

### 3. Intigriti Format
- **Header:** `[Bug Class]: [Exact Impact] in [Endpoint/Feature]`
- **CVSS Score:** CVSS 3.1 & 4.0 scores displayed at the top.
- **Summary & Root Cause:** Impact-first paragraph.
- **Steps to Reproduce:** Environment setup + verbatim HTTP wire requests + response snippets.
- **Business Risk:** Realistic adversary exploitation scenario.
- **Remediation:** Actionable fix.

### 4. Immunefi (Web3 / Smart Contract Format)
- **Title:** `[Bug Class] — [Protocol Name] — [Severity]`
- **Vulnerability Details:** Target Contract (`.sol`), Function name, Bug Class, Severity.
- **Root Cause:** Verbatim Solidity code block highlighting logic flaw.
- **Proof of Concept:** Foundry test (`forge test --match-test test_exploit -vvvv`).
- **Impact:** Quantified economic risk (e.g. "$X USD drained / Y% TVL loss").
- **Recommended Fix:** Before/after diff.

### 5. YesWeHack Format
- **Summary:** Concise vulnerability description.
- **Scope / Target:** Asset URI.
- **Reproduction Steps (PoC):** Numbered steps with raw HTTP traffic.
- **Security & Business Impact:** Quantified exploitation outcome.
- **Fix Recommendation:** Direct developer guidance.

---

## 4. CVSS 3.1 & CVSS 4.0 Quick Matrix

| Vulnerability Pattern | Privileges | CVSS 3.1 Vector | Score | Severity |
|---|---|---|---|---|
| Unauthenticated SQLi / Auth Bypass | None (`PR:N`) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8** | Critical |
| SSRF to Cloud IMDS / Metadata | None (`PR:N`) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` | **9.1** | Critical |
| Unauthenticated LFI / Source Leak | None (`PR:N`) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **7.5** | High |
| IDOR / BOLA (Read PII across users) | Low (`PR:L`) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` | **6.5** | Medium |
| Stored XSS in Authenticated Area | Low (`PR:L`) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | **5.4** | Medium |
| Open URL Redirection | None (`PR:N`) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N` | **4.7** | Medium |
| HTTP TRACE Enabled (XST) | None (`PR:N`) | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` | **3.1** | Low |

---

## 5. Downgrade Counter Library

When program triagers attempt to downgrade severity or claim out-of-scope / non-impact, counter with authoritative technical evidence:

- **"Requires Authentication / Low Privileges":**
  - *Counter:* "The vulnerability requires only a self-registered free account with zero administrative privileges. Any untrusted actor on the internet can register and exploit this immediately against all users."
- **"Theoretical / Limited Impact":**
  - *Counter:* "The captured response confirms verbatim exposure of sensitive PII/secrets. Automated iteration across IDs would allow full database/record extraction in minutes via a basic loop."
- **"Working as Intended / Feature":**
  - *Counter:* "No security documentation or industry standard specifies that user session A should receive unauthorized access to user session B's private objects. This directly violates tenant isolation and OWASP API1:2023."
- **"Missing Proof of Impact":**
  - *Counter:* "The report includes raw HTTP request and response pairs capturing the exact returned data from the server, confirming the flaw is live and fully reproducible."

---

## 6. Pre-Submission 60-Second Quality Gate

Before finalizing any report draft or running `/report`:
1. `[ ]` Title matches `[Bug Class] in [Endpoint] allows [Actor] to [Impact]`.
2. `[ ]` Sentence 1 gives the exact outcome/impact (not a textbook definition).
3. `[ ]` HTTP Request is complete and copy-pasteable (method, path, headers, body).
4. `[ ]` Response shows exact sensitive data returned (not just `200 OK`).
5. `[ ]` Two separate user accounts/roles documented for IDOR/BFLA tests.
6. `[ ]` CVSS 3.1 score and vector string calculated and verified.
7. `[ ]` Remediation is concise (1–2 actionable sentences with code guidance).
8. `[ ]` Zero instances of "could potentially", "may allow", or "might be possible".
