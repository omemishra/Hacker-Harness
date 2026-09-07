---
name: identity-saml-sso-abuse
description: SAML 2.0 single sign-on security assessment, XML Signature Wrapping (XSW), signature stripping, canonicalization attacks, and IdP confusion.
playbook: web-security
---

# Identity SAML 2.0 SSO Assessment

## Attack Vector Summary
SAML 2.0 vulnerabilities allow authentication bypasses and privilege escalation due to flawed XML signature verification in Service Providers (SPs). Common flaws include XML Signature Wrapping (XSW1–XSW8), signature stripping, comment injection in NameID, and Destination/Recipient parameter tampering.

## Tactical Heuristics & Step-by-Step Flow

### 1. SAML Interception & Decoding
Capture the `SAMLResponse` POST parameter from `/saml/sso` or `/saml/acs`:
```bash
# Decode base64 and decompress
echo "$SAML_RESPONSE" | base64 -d | xmllint --format -
```

### 2. XML Signature Wrapping (XSW) Attacks
XSW attacks duplicate the signed `<saml:Assertion>` or `<saml:Subject>` while modifying the unsigned clone that the application logic actually parses.

```text
# Common XSW Variants:
- XSW1: Cloned assertion added as child of Response, original placed in Extensions.
- XSW2: Cloned assertion added as child of Response, original placed after signatures.
- XSW3: Cloned assertion placed inside original assertion body.
- XSW4: Cloned assertion placed before original assertion.
- XSW7: Cloned assertion placed in KeyInfo with altered ID.
```

### 3. Signature Stripping & Comment Injection
- **Signature Stripping:** Remove `<ds:Signature>` entirely. If the SP fails to enforce signatures when unsigned responses are sent, full authentication bypass occurs.
- **XML Comment Injection (Truncation):**
  - Original: `<saml:NameID>admin@target.com</saml:NameID>`
  - Injected: `<saml:NameID>admin<!--comment-->@target.com.evil.com</saml:NameID>`
  - If XML parser extracts text before comment, SP authenticates as `admin`.

### 4. Destination & Audience Tampering
- Replace `<saml:Audience>` with target SP entity ID.
- Check if an Assertion signed for `app-a.target.com` is accepted by `app-b.target.com` (Cross-App Relay).

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| XML Signature Wrapping | SP verifies original signature but processes manipulated copy | Cloned `<Assertion>` with `NameID: admin@corp.com` | `302 Found` authenticated as admin user |
| Signature Stripping | SP verifies signature only if present; accepts unsigned | Deleted `<ds:Signature>` node | Authentication success without valid IdP certificate |
| Comment NameID Injection | Parser truncates username string at XML comment | `victim<!--evil-->@target.com` | Logged in as `victim@target.com` |
| IdP EntityID Substitution | SP accepts arbitrary metadata URL or untrusted IdP | `Issuer: https://attacker-idp.com` | Session established from attacker-controlled identity provider |

## Evidence Collection & Validation Gate
- Must capture raw modified `SAMLResponse` POST and resulting authenticated session cookie.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
