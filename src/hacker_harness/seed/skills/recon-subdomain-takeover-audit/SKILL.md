---
name: recon-subdomain-takeover-audit
description: Subdomain takeover identification, dangling CNAME DNS verification, and cloud provider fingerprint verification (AWS S3, GitHub, Heroku, Azure, Fastly).
playbook: web-security
---

# Subdomain Takeover & CNAME Hijacking Audit

## Attack Vector Summary
Subdomain takeover occurs when a DNS record (typically a `CNAME` or `A` record) points to a decommissioned external cloud service (AWS S3, GitHub Pages, Heroku, Azure Traffic Manager, Fastly, Shopify, Zendesk, Pantheon) where the asset has been deleted but the DNS entry remains active. An attacker can register the dangling resource name on the provider and claim control over the target's subdomain.

## Tactical Heuristics & Step-by-Step Flow

### 1. Dangling CNAME & DNS Resolution
Identify all unresolved or third-party CNAME records across discovered subdomains:
```bash
# Query CNAME and status
dig +noall +answer CNAME sub.target.com
```

### 2. Provider Fingerprint Verification
Match HTTP response headers and error bodies against canonical takeover signatures:

```text
# AWS S3:
CNAME: sub.target.com -> bucket.s3.amazonaws.com
Response: 404 Not Found
Body: "<Code>NoSuchBucket</Code>"

# GitHub Pages:
CNAME: sub.target.com -> org.github.io
Response: 404 Not Found
Body: "There isn't a GitHub Pages site here."

# Heroku:
CNAME: sub.target.com -> app.herokuapp.com
Response: 404 Not Found
Body: "No such app" or "Heroku | No such app"

# Azure App Service / Traffic Manager:
CNAME: sub.target.com -> app.azurewebsites.net
Response: 404 Not Found
Body: "404 Web Site not found"

# Fastly:
CNAME: sub.target.com -> fallback.global.fastly.net
Response: 500 / 404
Body: "Fastly error: unknown domain"
```

### 3. Verification Protocol (Non-Destructive)
- **Do NOT claim live assets unless authorized by scope.**
- Verify that the specific bucket/service name is currently available for registration on the provider.
- Document exact DNS resolution chain and HTTP response proof.

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Provider | DNS Pattern | Fingerprint Marker | Risk Level |
|---|---|---|---|
| AWS S3 | `*.s3.amazonaws.com` | `NoSuchBucket` | High (Cookie theft / XSS) |
| GitHub Pages | `*.github.io` | `There isn't a GitHub Pages site here.` | High (Session hijacking) |
| Heroku | `*.herokuapp.com` | `No such app` | High (Full subdomain control) |
| Azure Traffic Manager | `*.trafficmanager.net` | `404 Web Site not found` | High (Cloud tenant takeover) |
| Zendesk | `*.zendesk.com` | `Help Center Closed` | Medium (Phishing / Support hijacking) |

## Evidence Collection & Validation Gate
- Must capture `dig CNAME` output and raw HTTP response body showing unallocated service error.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
