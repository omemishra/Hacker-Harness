---
name: perimeter-vcenter-appliance-audit
description: VMware vSphere and vCenter Server external perimeter assessment — version fingerprinting, build detection, vRealize/vSAN upload endpoints, and Workspace ONE SAML metadata auditing.
---

# VMware vCenter & vSphere Perimeter Security Auditing

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Verified external VMware vCenter Server / Workspace ONE instances in `scope.yaml`.
- **Target Context:** Internet-exposed vCenter web management portals (`/ui`, `/sdk`, `/websso`).
- **Traffic Routing:** Route all HTTP/HTTPS probes through Caido proxy.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: Version & Build Fingerprinting
Extract exact appliance build metadata without active exploit execution:
```bash
# Query SOAP SDK Service version
GET /sdk/vimServiceVersions.xml HTTP/1.1
Host: {{ target }}

# Check Appliance REST API version (vSphere 7+)
GET /api/appliance/system/version HTTP/1.1
Host: {{ target }}

# UI build string from HTML source
GET /ui/login HTTP/1.1
Host: {{ target }}
```

### Step 2: Service Endpoint & SAML Metadata Enumeration
Inspect public SSO and metadata endpoints:
```bash
# SSO Metadata disclosure
GET /websso/SAML2/Metadata/vsphere.local HTTP/1.1
Host: {{ target }}

# SSO Admin Server info disclosure
GET /sso-adminserver/sdk/vsphere.local HTTP/1.1
Host: {{ target }}
```

### Step 3: Unauthenticated Plugin Endpoint Status Verification
Verify presence of legacy vulnerable plugin endpoints safely (using HEAD/GET baseline probes):
```bash
# vRealize plugin endpoint check
GET /ui/vropspluginui/rest/services/getstatus HTTP/1.1
Host: {{ target }}

# Workspace ONE OAuth verification endpoint baseline
GET /catalog-portal/ui/oauth/verify?error=&deviceUdid=probe HTTP/1.1
Host: {{ target }}
```

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Component | Vulnerability Mechanism | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **`vimServiceVersions.xml` Leak** | Public XML file details exact patch level | Direct GET returns full product and build numbers | `<versionId>7.0.3</versionId><build>18953952</build>` |
| **Workspace ONE Catalog Portal** | Unauthenticated FreeMarker template error | Probe `/catalog-portal/ui/oauth/verify` | Catalog portal FreeMarker exception in response body |
| **vRealize Plugin Exposure** | Exposed `/ui/vropspluginui/rest/services/` | Endpoint returns HTTP 200 or 405 instead of 404/401 | Plugin active on internet-facing interface |
| **SSO SAML Metadata Disclosure** | Public `/websso/SAML2/Metadata` | Extract entityID and internal hostname certificates | Disclosed internal AD domain or machine names |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture HTTP response headers and body showing exact build versions, XML metadata, or plugin endpoint responses.
2. **Impact Proof:** Document exposed perimeter administrative interfaces and outdated builds without running destructive arbitrary file upload or code execution exploits.
3. **Remediation:** Remove vCenter management interfaces from direct public internet exposure (place behind a secure VPN), apply VMware critical security patches, and disable unnecessary legacy plugins.
