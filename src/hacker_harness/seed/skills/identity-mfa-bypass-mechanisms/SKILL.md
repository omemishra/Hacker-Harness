---
name: identity-mfa-bypass-mechanisms
description: Multi-Factor Authentication (MFA / 2FA) bypass techniques, response manipulation, OTP race conditions, rate-limit circumvention, and session drop-off attacks.
playbook: web-security
---

# Identity MFA / 2FA Bypass Mechanisms

## Attack Vector Summary
MFA bypass vulnerabilities allow an attacker who possesses valid primary credentials (username + password) to circumvent secondary authentication checks (SMS/Email OTP, TOTP, push notifications, backup codes) due to state-management flaws, direct endpoint access, or missing server-side validation.

## Tactical Heuristics & Step-by-Step Flow

### 1. Direct Endpoint & Force Browsing
- After passing password authentication, skip the `/auth/mfa` verification step and directly request post-login authenticated resources (`/dashboard`, `/api/user/profile`, `/settings`).
- Check if the initial login response issues a valid session cookie before MFA verification.

### 2. Response & Status Code Manipulation
Intercept the MFA failure response (e.g., submitting `000000`) and manipulate response status/body:

```http
# Client submits invalid OTP
POST /api/v1/auth/verify-mfa HTTP/1.1
Host: target.com
{"otp":"000000"}

# Intercept and modify response from:
HTTP/1.1 401 Unauthorized
{"success":false,"error":"Invalid code"}

# To:
HTTP/1.1 200 OK
{"success":true,"token":"VALID_SESSION_TOKEN"}
```

### 3. Password Reset / OAuth 2FA Drop-off
- Initiate a password reset flow (`/forgot-password`). Check if resetting the password automatically logs the user in without prompting for the configured 2FA.
- Check if logging in via third-party OAuth (e.g. "Sign in with Google") bypasses mandatory tenant MFA policies.

### 4. OTP Race Conditions & Brute-force
- **Concurrency Burst:** Use single-packet attacks to submit multiple OTP attempts simultaneously before the attempt counter increments.
- **Rate Limit Circumvention:** Rotate headers (`X-Forwarded-For: 1.2.3.4`, `X-Real-IP`, `Client-IP`) or test if null/empty headers bypass IP rate limiting.

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| Response Code Manipulation | Client-side routing redirects on `status: 200` | Modify `401 Unauthorized` → `200 OK` | Access to authenticated dashboard and user session |
| Pre-MFA Token Usability | Initial login returns full session cookie | Use cookie received at `/login` directly | Successful API call without completing 2FA challenge |
| OAuth MFA Drop-off | Social login path ignores 2FA flag | Login via Google/GitHub to 2FA-enabled account | Immediate authenticated session without 2FA prompt |
| OTP Re-use / No Expiry | OTP code valid across multiple login sessions | Replay same 6-digit code | Second successful login using same OTP |

## Evidence Collection & Validation Gate
- Must capture request/response logs demonstrating authentication without valid 2FA token.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
