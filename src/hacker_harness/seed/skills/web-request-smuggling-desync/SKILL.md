---
name: web-request-smuggling-desync
description: HTTP Request Smuggling and Desync attacks, CL.TE, TE.CL, TE.TE obfuscation, HTTP/2 to HTTP/1.1 downgrade desync, request hijacking, and web cache poisoning.
---

# HTTP Request Smuggling & Request Desynchronization

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Check target front-end reverse proxies (Cloudflare, AWS ALB, Nginx, HAProxy) and back-end origin servers in `.hacker-harness/scope.yaml`.
- **Target Parameters:** Any HTTP/1.1 or HTTP/2 endpoints with reverse proxy infrastructure.
- **Traffic Routing:** Route raw TCP / HTTP requests with strict header preservation through Caido proxy.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: Front-End / Back-End Parsing Differential (CL.TE vs. TE.CL)

#### CL.TE Probe (Front-end uses `Content-Length`, Back-end uses `Transfer-Encoding`):
```http
POST / HTTP/1.1
Host: target.example.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
*If back-end processes chunked encoding, the smuggled `G` remains in the back-end socket buffer, causing the next request to become `GPOST / HTTP/1.1` $\rightarrow$ returns 405 Method Not Allowed or 400.*

#### TE.CL Probe (Front-end uses `Transfer-Encoding`, Back-end uses `Content-Length`):
```http
POST / HTTP/1.1
Host: target.example.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

### Step 2: Transfer-Encoding Obfuscation (TE.TE)
If both front-end and back-end support `Transfer-Encoding`, obfuscate the header so only one system ignores it:
```http
Transfer-Encoding: xchunked
Transfer-Encoding[tab]: chunked
Transfer-Encoding: chunked\r
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding: \x0bchunked
```

### Step 3: HTTP/2 Downgrade Request Smuggling (H2.CL / H2.TE)
When front-end translates HTTP/2 requests into HTTP/1.1 for back-end microservices:
1. **H2.TE:** Send an HTTP/2 request with a pseudo-header and an injected `transfer-encoding: chunked` header.
2. **H2.CL:** Send an HTTP/2 request with a misleading `content-length` header that differs from the actual HTTP/2 DATA frame length.
3. **CRLF Header Injection in H2:** Inject `\r\n` characters into HTTP/2 header names/values (`foo: bar\r\nTransfer-Encoding: chunked`).

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Desync Vector | Vulnerability Root Cause | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **Front-End Security Rule Bypass** | Front-end blocks `/admin`, back-end routes smuggled request | Smuggle `GET /admin HTTP/1.1` inside benign `POST /search` | Admin interface returned via public endpoint |
| **User Session Hijacking** | Next user request appended to smuggled POST body | Smuggle `POST /post/comment` with trailing `comment=` | Victim's cookies and session token posted as a comment |
| **Web Cache Poisoning** | Smuggled 302 redirect response saved into cache for `/` | Smuggle request returning redirect to attacker host | All website visitors redirected to external host |
| **OAuth Code Interception** | Smuggled request prepended to victim's OAuth callback | Victim hits `/oauth/callback?code=xyz` $\rightarrow$ appends to attacker query | Victim's code saved to attacker profile |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture precise timing and response code differentials (e.g. 404/405 error caused by prepended prefix `GPOST`) across dual request chains.
2. **Impact Proof:** Demonstrate request desync against dedicated test accounts/endpoints without disrupting other user sessions or shared caches.
3. **Remediation:** Disable HTTP request reuse/pipelining on back-end connections, use end-to-end HTTP/2 without protocol downgrading, and enforce RFC 7230 compliance (reject requests with both `Content-Length` and `Transfer-Encoding`).
