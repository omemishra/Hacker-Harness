---
name: code-review-deep-audit
description: Comprehensive Source Code Security Review (SAST, taint tracking, framework-specific vulnerability patterns, and business logic analysis).
playbook: web-security
---

# Code Review Deep Audit

## Attack Vector Summary
Source code security review involves multi-engine static analysis (SAST), taint tracking from input sources (controllers, routers, query params) to dangerous sinks (database queries, shell executions, filesystem I/O, deserializers), middleware audit, supply chain scanning, and business logic verification.

## Tactical Heuristics & Step-by-Step Flow

### 1. Technology & Architecture Discovery
Map dependencies, entrypoints, and routing layers:
- Dependency files: `package.json`, `requirements.txt`, `Gemfile`, `go.mod`, `pom.xml`, `composer.json`, `Cargo.toml`.
- Framework routers: Django `urls.py`, Rails `routes.rb`, Express `app.use()`, FastAPI routers, Spring `@RequestMapping`.

### 2. Multi-Engine SAST, Bandit & Medusa Tool Execution Matrix
Run specialized static security scanners across the target repository tree:

```bash
# 1. Semgrep (Multi-language SAST & OWASP Top 10 Taint Tracking)
semgrep --config "p/owasp-top-ten" --config "p/security-audit" --config "p/secrets" \
  --json -o Recon/target_code_review_semgrep.json /path/to/repo
semgrep --config auto /path/to/repo 2>/dev/null | tee Recon/target_code_review_semgrep.txt

# 2. Bandit (Python Security Linter & AST Vulnerability Scanner)
if find /path/to/repo -name "*.py" | head -1 | grep -q .; then
  bandit -r /path/to/repo -f json -o Recon/target_code_review_bandit.json 2>/dev/null
  bandit -r /path/to/repo -f txt 2>/dev/null | tee Recon/target_code_review_bandit.txt
fi

# 3. Medusa (40,000+ Detection Patterns: SAST, Supply Chain & Secret Extraction)
if command -v medusa &>/dev/null; then
  medusa scan /path/to/repo --output Recon/target_code_review_medusa.txt
fi

# 4. Malcontent (14,500+ YARA Rules for Supply Chain Compromise Detection)
if command -v malcontent &>/dev/null; then
  malcontent analyze /path/to/repo --min-risk medium --format markdown \
    -o Recon/target_code_review_malcontent.md 2>/dev/null
fi

# 5. Bearer (Data Flow & Privacy/Security SAST)
if command -v bearer &>/dev/null; then
  bearer scan /path/to/repo --format json --output Recon/target_code_review_bearer.json
fi

# 6. Dependency Vulnerability Auditing (SCA)
trivy fs --scanners vuln,secret,config /path/to/repo -f json -o Recon/target_code_review_trivy.json
npm audit --json > Recon/npm_audit.json 2>/dev/null
pip-audit -r requirements.txt -f json > Recon/pip_audit.json 2>/dev/null
```

### 3. Source-to-Sink Taint Matrix
```text
# 1. SQL Injection Sinks
- Raw query execution: raw(), execute(), query(), db.raw(), EntityManager.createNativeQuery()
- String concatenation / template formatting inside SQL statements.

# 2. Command Injection & RCE Sinks
- Process execution: exec(), spawn(), system(), subprocess.Popen(shell=True), Runtime.getRuntime().exec()
- Dynamic evaluation: eval(), Function(), vm.runInThisContext(), dangerous YAML/pickle loading.

# 3. File System & Path Traversal Sinks
- File readers / writers: fs.readFile(), open(), include, require, send_file(), File.read()
- Path joining without normalization: path.join() with user input starting with "/".

# 4. Insecure Deserialization Sinks
- Object deserializers: pickle.loads(), yaml.load(Loader=Loader), unserialize(), readObject(), JSON.parse with prototype access.
```

### 4. Supply Chain & Dependency Abuse Checks
- **Typosquatting Risk:** Inspect `package.json`, `Gemfile`, `requirements.txt` for common typo variants (`requst`, `expresss`, `angualr`, `reacct`, `lodashh`).
- **Dependency Confusion:** Search for internal/private package prefixes (`internal-`, `company-`) published to public registries.
- **Untrusted CI/CD Actions:** Inspect `.github/workflows/*.yml` for unpinned third-party actions (`uses: org/action@master`).
- **Suspicious Install Scripts:** Check `postinstall`, `preinstall`, and `Makefile` for curl pipes (`curl ... | sh`, `wget ... | bash`).

### 5. Authentication, Authorization & RBAC Audit
- Inspect authorization decorators/middleware: `@login_required`, `@permission_required`, `before_action :authenticate_user!`, Spring `@PreAuthorize`.
- Check for missing object-level ownership checks (IDOR/BOLA): verify if queries filter by `tenant_id` or `user_id == current_user.id`.
- Review session token generation, signature validation, and cookie security flags (`HttpOnly`, `Secure`, `SameSite`).

### 6. Business Logic & State Machine Flaws
- Payment and billing flows: price calculations, coupon re-use, negative amounts, race conditions.
- Account operations: password reset token expiration, single-use enforcement, 2FA drop-off bypasses.

## Reporting Standards — Line-Numbered Code Citation
Every finding must cite exact file path, line numbers, impact, and actionable fix:

```markdown
### P1: Remote Code Execution via Insecure Deserialization
**File:** `app/services/report_processor.py:42-55`
**Type:** Insecure Deserialization (CWE-502)
**Impact:** Unauthenticated RCE via arbitrary Python object execution in background queue.
**Vulnerable Snippet:**
```python
def process_incoming_job(raw_payload):
    # Insecure deserialization of untrusted user input
    job_data = pickle.loads(base64.b64decode(raw_payload))
    return job_data.run()
```
**Remediation:** Replace `pickle.loads` with strict JSON schema parsing (`json.loads` + Pydantic model).
```

## Evidence Collection & Validation Gate
- Must provide exact file path, line numbers, and end-to-end data flow explanation.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
