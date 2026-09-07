---
hackerHarness:
  strict: true
---

# Recon Framework — Hacker-Harness 20-Stage Reconnaissance Methodology

This is Hacker-Harness: you plan, you execute, you write file-gated deliverables. All 20 reconnaissance stages (R1–R20) and exploitation gates are structured with exact input/output file contracts, tool utilization commands, and tactical skills. Do not start the next phase until `methodology_advance` succeeds.

**Scope Types:**
- **SCOPEONLY** (default) — single target hostname/URL. Restrict all tools (`katana`, `gau`, `waybackurls`, `arjun`) to the exact domain.
- **WILDCARD** — full subdomain discovery enabled across registered root domains (`subfinder`, `gau --subs`, `amass`, `crt.sh`).

**Traffic & Proxy Rules:**
- **Passive Discovery:** `gau`, `waybackurls`, `whatweb`, DNS lookup, `crt.sh` — direct execution allowed.
- **Active Probing & Crawling:** `katana`, `arjun`, `OpenRedirex`, `feroxbuster`, injection fuzzing — route through Caido MCP (`caido_send_request`) or local proxy `curl -x http://127.0.0.1:8080 -k`.

Print `✓ Methodology loaded. Starting R{N}.` after `skill_load` for this phase.

## Canonical File Directory Layout
```text
Recon/
├── scope_summary.md               # R0 — Authorization scope, mode, and target boundaries
├── target_sensitive_files.txt     # R1 — Probe results (.git, .env, backups, keys)
├── dotfiles.txt                   # R1 — Accessible config paths
├── leaked_secrets.txt             # R1 — Extracted credentials or API tokens
├── target_katana.txt              # R2 — Actively crawled endpoints and assets
├── target_gau.txt                 # R3 — Historical URLs from AlienVault / CommonCrawl
├── target_wayback.txt             # R3 — Historical URLs from Wayback Machine
├── GW_emails.txt                  # R4a — Discovered employee/admin email addresses (>=5 instances)
├── GW_live_tokens.txt             # R4b — Verified live URL tokens and authenticated links
├── GW_files.txt                   # R4c — Accessible documents (PDF, CSV, Excel, SQL dumps)
├── gwjs_endpoints.txt             # R5 — JavaScript discovered endpoints and routes
├── js_secrets.txt                 # R5 — Secrets and API keys extracted from JS
├── target_postmessage.txt         # R5 — Discovered window postMessage event listeners
├── jsbundles/                     # R5 — Downloaded JavaScript bundles
├── target_recovered_sources.txt   # R6 — Unpacked source map source trees
├── mined_endpoints.txt            # R7 — Endpoints with active parameters discovered via Arjun
├── GWJSAJQ_urls.txt               # R7 — Merged, deduplicated URLs with parameter shapes (R3+R5+Arjun)
├── ptLFI.txt                      # R7 — Path traversal and file parameter candidates
├── target_whatweb.txt             # R8 — Web technologies, server, framework fingerprint
├── target_csp_domains.txt         # R9 — Extracted CSP whitelisted domains
├── target_csp_bypass_payloads.txt # R9 — Matched CSPBypass gadget payloads
├── security_headers.md            # R9 — Missing security headers & cookie security audit
├── GW_open_redirect.txt           # R10 — Open redirect parameters from archive URLs
├── AQ_redirect.txt                # R10 — Open redirect parameters from Arjun
├── P_O_Redirect.txt               # R10 — Merged candidate redirect URLs
├── P_O_Redirect_findings.txt      # R10 — Confirmed open redirect vulnerabilities
├── psqli.txt                      # R11 — SQL injection candidate parameters
├── target_cspp_findings.txt       # R12 — Confirmed prototype pollution properties & sinks
├── target_ssrf_params.txt         # R13 — SSRF candidate parameter endpoints
├── target_oob_callbacks.txt       # R13 — Interactsh / OOB callback verification log
├── target_sqli_exploited.txt      # E1 — Verified SQL injection database extraction PoCs
├── target_lfi_exploited.txt       # E2 — Verified LFI / Path traversal file read PoCs
├── target_gh_dorks.txt            # R14 — GitHub dork search results
├── target_trufflehog.txt          # R14 — TruffleHog live verified secret findings
├── target_gh_pr_leaks.txt         # R14 — PR and issue discussion secret leaks
├── target_gh_commit_leaks.txt     # R14 — Historical commit log credential extractions
├── target_code_review_semgrep.txt # R15 — Semgrep SAST & taint tracking findings
├── target_code_review_bearer.txt  # R15 — Bearer data-flow & privacy findings
├── target_code_review_sca.txt     # R15 — Dependency vulnerability audit (Trivy/npm/pip)
├── target_code_review_report.md   # R15 — Source review report with line-numbered citations
├── target_ports.txt               # R16 — External port scanning results (Naabu/Nmap)
├── target_ferox.txt               # R17 — Feroxbuster / ffuf directory fuzzing endpoints
├── target_403_bypasses.txt        # R18 — 403/401 restriction bypasses (headers, rewrite URLs)
├── target_cors_findings.txt       # R19 — Confirmed CORS origin reflection & credentials leaks
├── target_crtsh.txt               # R20 — Certificate transparency subdomains and SAN entries
├── publicindex.md                 # Master Public Index and surface mapping report
└── recon_summary.md               # Executive Reconnaissance Summary and findings ledger
```

---

## R0: Scope Verification & Policy Pre-flight
Load `genpentest-overview`. Validate target authorization scope (SCOPEONLY vs WILDCARD), reachability, and tool availability.
- **Requires:** None
- **Required writes:** `Recon/scope_summary.md`

## R1: Sensitive File Exposure (.git, .env, credentials)
Load `genpentest-p2-public-index`.
- Probe 58 high-risk paths: `.git/config`, `.env`, `.env.production`, `credentials.json`, `secrets.yaml`, `.aws/credentials`, `backup.sql`, `docker-compose.yml`, `phpinfo.php`, `id_rsa`.
- **Contextual Sub-Skills:** `perimeter-vpn-gateway-audit`, `perimeter-vcenter-appliance-audit`, `perimeter-exchange-ntlm-info`, `cloud-aws-iam-privesc`, `recon-subdomain-takeover-audit`, `mobile-apk-decompilation-audit`, `supply-chain-cicd-audit`.
- **Requires:** `Recon/scope_summary.md`
- **Required writes:** `Recon/target_sensitive_files.txt`, `Recon/dotfiles.txt`, `Recon/leaked_secrets.txt`

## R2: Web Crawling (katana)
Load `genpentest-p2-public-index`.
- Run: `katana -u https://target.com -d 3 -jc -kf -o Recon/target_katana.txt`
- **Requires:** `Recon/scope_summary.md`
- **Required writes:** `Recon/target_katana.txt`

## R3: URL Extraction (gau + waybackurls)
Load `genpentest-p2-public-index`.
- Run: `gau https://target.com | tee Recon/target_gau.txt`
- Run: `waybackurls https://target.com | tee Recon/target_wayback.txt`
- **Requires:** `Recon/scope_summary.md`
- **Required writes:** `Recon/target_gau.txt`, `Recon/target_wayback.txt`

## R4: Responsive Analysis (Emails, Live Tokens, Sensitive Documents)
Load `genpentest-p2-public-index`. If JWTs appear, load `identity-jwt-manipulation`.
- **4a Email Discovery:** Extract emails occurring $\ge 5$ times into `Recon/GW_emails.txt`.
- **4b Token Discovery:** Extract `token=`, `access_token=`, `jwt=`, `api_key=`, `secret=` and test live validity against endpoints into `Recon/GW_live_tokens.txt`.
- **4c Sensitive Document Discovery:** Catalog exposed `.pdf`, `.xlsx`, `.csv`, `.sql`, `.doc` into `Recon/GW_files.txt`.
- **Requires:** `Recon/target_gau.txt`, `Recon/target_wayback.txt`
- **Required writes:** `Recon/GW_emails.txt`, `Recon/GW_live_tokens.txt`, `Recon/GW_files.txt`

## R5: JavaScript Bundle Analysis (Endpoints, Secrets, postMessage)
Load `genpentest-p3-js-analysis`. If GraphQL endpoints appear, load `web-graphql-introspection-bypass`.
- Download active JS bundles into `Recon/jsbundles/`.
- Extract API routes via `jsluice` / regex into `Recon/gwjs_endpoints.txt`.
- Extract hardcoded developer keys into `Recon/js_secrets.txt`.
- Extract `window.addEventListener("message", ...)` sinks into `Recon/target_postmessage.txt`.
- **Requires:** `Recon/target_katana.txt`
- **Required writes:** `Recon/gwjs_endpoints.txt`, `Recon/js_secrets.txt`, `Recon/target_postmessage.txt`

## R6: Source Map Extraction
Load `genpentest-p3-js-analysis`.
- Check `.map` files (e.g. `main.js.map`), unpack source trees using `sourcemapper` or unwebpack, and search unminified sources for internal endpoints and keys.
- **Requires:** `Recon/gwjs_endpoints.txt`
- **Required writes:** `Recon/target_recovered_sources.txt`

## R7: Parameter Discovery & Test URL Synthesis (Arjun + qsreplace)
Load `genpentest-p3-js-analysis`.
- Merge base paths from R3 + R5 (`gwjs_endpoints.txt`).
- Run `arjun -u ...` to produce `Recon/mined_endpoints.txt`.
- Merge and deduplicate all query-parameter URLs into `Recon/GWJSAJQ_urls.txt`.
- Extract path traversal / file parameter candidates into `Recon/ptLFI.txt`.
- **Requires:** `Recon/gwjs_endpoints.txt`, `Recon/target_gau.txt`
- **Required writes:** `Recon/mined_endpoints.txt`, `Recon/GWJSAJQ_urls.txt`, `Recon/ptLFI.txt`

## R8: Technology Fingerprinting (whatweb)
Load `genpentest-overview`.
- Fingerprint server, framework, OS, and CMS with `whatweb -a 3 https://target.com`.
- **Requires:** `Recon/scope_summary.md`
- **Required writes:** `Recon/target_whatweb.txt`

## R9: Security Headers Check & CSP Bypass
Load `genpentest-overview` and `web-xss-polyglot-execution`.
- Extract `Content-Security-Policy` domains into `Recon/target_csp_domains.txt`.
- Query **CSPBypass (`data.tsv`)** for matching JSONP, Angular, and CDN gadgets, saving to `Recon/target_csp_bypass_payloads.txt`.
- Audit missing headers (`HSTS`, `X-Frame-Options`, cookie flags) into `Recon/security_headers.md`.
- **Requires:** `Recon/target_whatweb.txt`
- **Required writes:** `Recon/target_csp_domains.txt`, `Recon/target_csp_bypass_payloads.txt`, `Recon/security_headers.md`

## R10: Open Redirect (OpenRedirex & Filter Bypasses)
Load `web-open-redirect-audit`.
- Collect redirect parameters from gau/wayback (`GW_open_redirect.txt`) and Arjun (`AQ_redirect.txt`).
- Merge into `P_O_Redirect.txt` and run `openredirex` with bypass list (`//`, `/\\`, `@` authority hijack, CRLF).
- Record confirmed findings in `Recon/P_O_Redirect_findings.txt`.
- **Requires:** `Recon/GWJSAJQ_urls.txt`
- **Required writes:** `Recon/GW_open_redirect.txt`, `Recon/AQ_redirect.txt`, `Recon/P_O_Redirect.txt`, `Recon/P_O_Redirect_findings.txt`

## R11: Active Vulnerability Probing (XSS, SQLi, SSTI, IDOR)
Load `genpentest-p4-client-side`, `web-xss-polyglot-execution`, `web-sqli-blind-polyglot`, `web-ssti-engine-rce`, `web-idor-bola-authorization`, `web-api-mass-assignment-pollution`.
- Run fuzzing sweeps across `Recon/GWJSAJQ_urls.txt` using Caido proxy.
- Extract potential SQL injection parameters into `Recon/psqli.txt`.
- **Requires:** `Recon/GWJSAJQ_urls.txt`, `Recon/target_csp_bypass_payloads.txt`
- **Required writes:** `Recon/psqli.txt`

## R12: Client-Side Prototype Pollution (CSPP)
Load `web-prototype-pollution-cspp`.
- Test URL query parameters and hash fragments (`?__proto__[test]=polluted`, `?constructor.prototype.test=polluted`).
- Audit client-side scripts in `Recon/jsbundles/` for `deparam`, `merge`, and gadget execution sinks.
- **Requires:** `Recon/GWJSAJQ_urls.txt`, `Recon/jsbundles/`
- **Required writes:** `Recon/target_cspp_findings.txt`

## R13: SSRF Testing & Blind XSS Out-Of-Band
Load `web-ssrf-cloud-pivot`.
- Identify URL/webhook parameter endpoints into `Recon/target_ssrf_params.txt`.
- Test cloud IMDS endpoints (`http://169.254.169.254/latest/meta-data/`) and interactsh OOB callbacks.
- Record verified network interactions in `Recon/target_oob_callbacks.txt`.
- **Requires:** `Recon/GWJSAJQ_urls.txt`
- **Required writes:** `Recon/target_ssrf_params.txt`, `Recon/target_oob_callbacks.txt`

---

## OPTIONAL EXPLOITATION GATES (E1 / E2 / E3)

### E1: SQL Injection Active Verification
Load `web-sqli-blind-polyglot`.
- Run `sqlmap -m Recon/psqli.txt --batch --random-agent --tamper=between,randomcase` on confirmed leads.
- **Requires:** `Recon/psqli.txt`
- **Required writes:** `Recon/target_sqli_exploited.txt`

### E2: LFI & Path Traversal Verification
Load `web-lfi-path-traversal-audit`.
- Test parameters in `Recon/ptLFI.txt` against `/etc/passwd`, `C:\Windows\win.ini`, and `/proc/self/environ`.
- **Requires:** `Recon/ptLFI.txt`, `Recon/target_whatweb.txt`
- **Required writes:** `Recon/target_lfi_exploited.txt`

---

## STANDALONE INFRASTRUCTURE & OSINT (R14–R20)

### R14: GitHub Recon & Organization Dorking
Load `code-repo-secret-audit`.
- Run GitHub dorks (`target_gh_dorks.txt`), TruffleHog live scans (`target_trufflehog.txt`), and commit/PR leak inspections (`target_gh_pr_leaks.txt`, `target_gh_commit_leaks.txt`).
- **Requires:** `Recon/scope_summary.md`
- **Required writes:** `Recon/target_gh_dorks.txt`, `Recon/target_trufflehog.txt`, `Recon/target_gh_pr_leaks.txt`, `Recon/target_gh_commit_leaks.txt`

### R15: Code Review & Deep Static Analysis
Load `code-review-deep-audit`.
- Execute Semgrep (`target_code_review_semgrep.txt`), Bearer (`target_code_review_bearer.txt`), and SCA dependency auditing (`target_code_review_sca.txt`).
- Generate detailed findings report with exact file:line references in `Recon/target_code_review_report.md`.
- **Requires:** Local clone or target repo path
- **Required writes:** `Recon/target_code_review_semgrep.txt`, `Recon/target_code_review_bearer.txt`, `Recon/target_code_review_sca.txt`, `Recon/target_code_review_report.md`

### R16: Port Scanning (Naabu / Nmap)
Load `perimeter-port-service-fuzz`.
- Run: `naabu -host target.com -p - | nmap -sV -sC -iL - -oN Recon/target_ports.txt`
- **Requires:** `Recon/scope_summary.md`
- **Required writes:** `Recon/target_ports.txt`

### R17: Directory & Endpoint Fuzzing (Feroxbuster / ffuf)
Load `perimeter-port-service-fuzz`.
- Run: `feroxbuster -u https://target.com -w /usr/share/wordlists/dirb/common.txt -o Recon/target_ferox.txt`
- **Requires:** `Recon/scope_summary.md`
- **Required writes:** `Recon/target_ferox.txt`

### R18: 403/401 Restriction Bypass
Load `perimeter-port-service-fuzz`.
- Test endpoints from `target_ferox.txt` with path normalization (`/..;/`, `/%2e/`), rewrite headers (`X-Original-URL`, `X-Rewrite-URL`, `X-Custom-IP-Authorization: 127.0.0.1`), and HTTP method swaps.
- **Requires:** `Recon/target_ferox.txt`
- **Required writes:** `Recon/target_403_bypasses.txt`

### R19: CORS Misconfiguration Check
Load `web-cors-misconfiguration-bypass`.
- Probe origin reflection with credentials (`Origin: https://evil.com`, `Origin: null`, prefix/suffix domains) across all active API endpoints.
- **Requires:** `Recon/gwjs_endpoints.txt`
- **Required writes:** `Recon/target_cors_findings.txt`

### R20: Certificate Transparency & Subdomain Mining (crt.sh)
Load `recon-subdomain-takeover-audit`.
- Query `crt.sh/?q=%.target.com&output=json` to extract SAN hostnames and historical certificates.
- **Requires:** `Recon/scope_summary.md`
- **Required writes:** `Recon/target_crtsh.txt`

---

## Consolidation & Master Validation Gate
- Synthesize all discovered assets, endpoints, and confirmed leads into `Recon/publicindex.md` and `Recon/recon_summary.md`.
- Run `/validate` across all leads to enforce the 7-Question Validation Gate.
- **Requires:** All phase outputs
- **Required writes:** `Recon/publicindex.md`, `Recon/recon_summary.md`
