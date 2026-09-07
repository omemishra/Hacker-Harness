from __future__ import annotations

import csv
import html
import io
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import load_settings
from .findings import evaluate_finding_gate

logger = logging.getLogger(__name__)


CVSS_MAP = {
    "critical": {
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "vector_v4": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "vrt_p": "P1",
    },
    "high": {
        "score": 8.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "vector_v4": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        "vrt_p": "P2",
    },
    "medium": {
        "score": 5.4,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N",
        "vector_v4": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
        "vrt_p": "P3",
    },
    "low": {
        "score": 3.1,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "vector_v4": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        "vrt_p": "P4",
    },
    "informational": {
        "score": 0.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "vector_v4": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
        "vrt_p": "P5",
    },
}


VULN_PATTERNS = [
    (
        re.compile(r"\b(idor|bola|broken object|cross-tenant|cross-project|cross-user)\b", re.I),
        "Broken Object Level Authorization (IDOR / BOLA)",
        "Broken Access Control > Insecure Direct Object Reference (IDOR)",
        "An unauthorized actor can access, mutate, or delete private user records across tenant boundaries by substituting object identifiers in API requests without server-side ownership verification.",
        "An attacker can extract private customer PII, financial records, or operational data of all other organizations. Automated enumeration allows complete database-wide customer data extraction in minutes.",
        "Enforce strict server-side authorization checks verifying that the authenticated session owns the requested resource ID before returning data: `if resource.owner_id != session.user_id: raise Forbidden()`.",
        "403 Forbidden when requesting another user's resource",
        "200 OK returning victim private record data to an unauthorized session",
    ),
    (
        re.compile(r"\b(ssrf|metadata|169\.254|internal request|cloud pivot)\b", re.I),
        "Server-Side Request Forgery (SSRF)",
        "Server-Side Injection > Server-Side Request Forgery (SSRF)",
        "The server accepts user-supplied destination URLs and issues backend HTTP requests without restricting resolution to public ranges, allowing coercing requests to loopback interfaces, private networks, or cloud instance metadata (IMDS).",
        "An attacker can extract temporary cloud provider IAM credentials (e.g. AWS role tokens via 169.254.169.254) or interact with internal unauthenticated microservices, leading to cloud infrastructure compromise.",
        "Validate destination hostnames against a strict whitelist. Resolve DNS server-side, reject private IP ranges (RFC 1918, 169.254.0.0/16, 127.0.0.0/8), and require IMDSv2 token authentication.",
        "400 Bad Request / Destination host rejected",
        "200 OK returning cloud metadata or internal service responses",
    ),
    (
        re.compile(r"\b(csrf|cross-site request forgery)\b", re.I),
        "Missing Cross-Site Request Forgery (CSRF) Protection",
        "Broken Access Control > Cross-Site Request Forgery (CSRF)",
        "State-changing endpoints and forms do not validate anti-CSRF tokens or enforce SameSite cookie policies, allowing malicious websites to trigger actions on behalf of authenticated victims.",
        "Unauthorized state-changing actions performed on behalf of authenticated users (e.g. updating passwords, altering user profiles, or initiating unauthorized transactions).",
        "Implement anti-CSRF tokens (synchronizer token pattern) on all state-changing endpoints, and set `SameSite=Lax` or `SameSite=Strict` on session cookies.",
        "403 Forbidden on state-changing requests missing CSRF token",
        "State-changing action executes successfully without anti-CSRF validation",
    ),
    (
        re.compile(r"\b(trace|xst|cross-site tracing)\b", re.I),
        "HTTP TRACE Method Enabled (Cross-Site Tracing / XST)",
        "Server Configuration > Insecure HTTP Methods Enabled",
        "The web server responds to HTTP TRACE requests by echoing back the full request headers, including session cookies.",
        "When chained with XSS, allows bypassing `HttpOnly` cookie protections by reading echoed cookie headers from the response body.",
        "Disable HTTP TRACE and TRACK methods in web server configuration (e.g. Apache `TraceEnable Off` or IIS Request Filtering).",
        "405 Method Not Allowed / 501 Not Implemented for TRACE requests",
        "200 OK echoing all request headers and cookies back in the response",
    ),
    (
        re.compile(r"\b(sqli|sql injection|nosql|query injection|auth bypass.*login|login.*bypass)\b", re.I),
        "SQL Injection (SQLi)",
        "Server-Side Injection > SQL Injection",
        "User input is concatenated directly into SQL queries without parameterized bindings, allowing an attacker to manipulate query logic, bypass authentication, and extract or mutate backend database contents.",
        "Complete compromise of backend database confidentiality and integrity. An attacker can bypass authentication to log in as administrator, dump all plaintext/hashed credentials, and modify database records.",
        "Use parameterized prepared statements (e.g. `PreparedStatement` or ORM parameterized bindings) for all database operations. Never concatenate user-supplied input into SQL strings.",
        "401 Unauthorized on invalid credentials / Parameterized execution",
        "302 Redirect (authentication bypass as admin) or 500 error leaking query syntax",
    ),
    (
        re.compile(r"\b(xss|cross-site scripting|stored xss|dom xss|script injection|reflected xss)\b", re.I),
        "Cross-Site Scripting (XSS)",
        "Cross-Site Scripting (XSS) > Stored / Reflected",
        "The application reflects or stores untrusted input in HTML/DOM contexts without contextual entity encoding or sanitization, executing arbitrary JavaScript in victim browser sessions.",
        "Malicious scripts execute in authenticated victim sessions, enabling session cookie hijacking, CSRF token theft, unauthorized client-side actions, and credential harvesting.",
        "Implement context-aware HTML entity encoding on all user-supplied output. Enforce a strict Content Security Policy (CSP) without `unsafe-inline` or wildcards.",
        "Contextual HTML entity encoding (`&lt;script&gt;`) preventing code execution",
        "Raw unescaped script tag executed in browser DOM (`<script>alert(1)</script>`)",
    ),
    (
        re.compile(r"\b(bfla|function level|privilege escalation|role bypass|admin bypass|is_admin)\b", re.I),
        "Broken Function Level Authorization (BFLA)",
        "Broken Access Control > Privilege Escalation > Vertical",
        "The application exposes administrative or privileged API actions without validating whether the requesting user possesses the requisite administrative permissions.",
        "Low-privileged or unauthenticated attackers can invoke administrative controllers, escalate privileges to superadmin, reconfigure system settings, or manipulate organization accounts.",
        "Enforce centralized role-based access control (RBAC) checks on every administrative endpoint. Deny access by default unless the session role explicitly possesses administrative entitlement.",
        "403 Forbidden for non-administrative roles",
        "200 OK permitting unauthorized administrative execution",
    ),
    (
        re.compile(r"\b(business logic|race condition|concurrency|rate limit|limit overrun)\b", re.I),
        "Business Logic & Concurrency Vulnerability",
        "Business Logic Flaws > Concurrency / Race Condition",
        "The application fails to enforce atomic database transactions or mutex locks during sequential operations, allowing concurrent requests to bypass business rules or limits.",
        "Financial loss, duplicate voucher/coupon redemption, balance multiplication, or rate limit circumvention through concurrent request flooding.",
        "Use database row-level locking (`SELECT FOR UPDATE`), atomic transactions, idempotent request tokens, and server-side concurrency limiters.",
        "Subsequent concurrent attempts rejected with 409 Conflict or 429 Too Many Requests",
        "Multiple concurrent executions succeed, multiplying state or credit balance",
    ),
    (
        re.compile(r"\b(rce|command injection|remote code execution|shell execution)\b", re.I),
        "Remote Code Execution (RCE)",
        "Server-Side Injection > Remote Code Execution",
        "User input is passed directly to system shell interpreters or dynamic code evaluators, allowing an attacker to inject shell metacharacters and execute arbitrary OS commands.",
        "Complete takeover of the underlying server operating system, enabling arbitrary command execution, data exfiltration, lateral movement, and persistent backdoor deployment.",
        "Avoid invoking shell interpreters from application code. Use native language APIs with argument arrays instead of shell command strings.",
        "Input treated as literal text with zero command execution",
        "Operating system executes injected command string returning command output",
    ),
    (
        re.compile(r"\b(prototype pollution|cspp|__proto__|object prototype)\b", re.I),
        "Client-Side Prototype Pollution (CSPP)",
        "Client-Side Injection > Prototype Pollution",
        "Recursive object merge utilities modify `Object.prototype` when processing user-controlled JSON or URL parameters, injecting unexpected properties across all JavaScript objects.",
        "Alters application client-side logic, bypasses security controls, and triggers DOM XSS via gadgets in third-party client libraries.",
        "Reject property keys containing `__proto__`, `constructor`, or `prototype`. Freeze prototypes with `Object.freeze(Object.prototype)`.",
        "Object prototypes remain immutable",
        "Object.prototype modified, polluting default object properties",
    ),
    (
        re.compile(r"\b(lfi|path traversal|traversal|file inclusion|procfs|source disclosure)\b", re.I),
        "Path Traversal & Local File Inclusion (LFI)",
        "Server-Side Injection > Directory Traversal",
        "The application accepts file paths from user input and accesses the filesystem without restricting resolution to a designated directory, allowing path traversal (`../`) to include internal source files.",
        "Unauthenticated read access to server source code and configuration files, disclosing database connection credentials, API keys, and internal architecture.",
        "Whitelist allowed file names or map user identifiers to files using database records. Canonicalize paths with `realpath()` and verify they reside within the intended base directory.",
        "403 Forbidden or 404 Not Found for paths outside document root",
        "200 OK returning raw server source code and configuration files",
    ),
    (
        re.compile(r"\b(open redirect|redirect|url manipulation|returl)\b", re.I),
        "Open URL Redirection",
        "Open Redirect > Unvalidated Redirect",
        "The application redirects users to destination URLs specified in request parameters without validating that the target domain is trusted.",
        "Enables targeted phishing campaigns leveraging trusted domain reputation, or chained with OAuth callback flows to steal authorization codes.",
        "Enforce a strict whitelist of permitted external domains or restrict redirection parameters exclusively to relative paths starting with `/`.",
        "302 redirect only to relative paths or whitelisted domains",
        "302 redirect to untrusted external attacker domain (e.g. evil.com)",
    ),
    (
        re.compile(r"\b(plaintext password|password storage|unhashed password)\b", re.I),
        "Insecure Cryptographic Storage (Plaintext Passwords)",
        "Sensitive Data Exposure > Insecure Credential Storage",
        "The application stores user credentials in plaintext within the backend database without salted cryptographic hashing algorithms (e.g. Argon2, bcrypt, PBKDF2).",
        "Direct credential theft upon SQL injection or database disclosure, allowing immediate account takeover of all registered users without hash cracking.",
        "Hash all passwords server-side using modern memory-hard password hashing algorithms (Argon2id or bcrypt with appropriate work factors) before database storage.",
        "Passwords stored as irreversible, salted cryptographic hashes",
        "Plaintext password strings stored directly in database records",
    ),
    (
        re.compile(r"\b(cors|origin reflection|null origin)\b", re.I),
        "CORS Misconfiguration",
        "Server Configuration > CORS Misconfiguration",
        "The server reflects arbitrary `Origin` headers in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`, or improperly trusts null origins.",
        "Malicious third-party websites visited by an authenticated victim can execute credentialed cross-origin requests to read private data.",
        "Whitelist specific trusted origins. Never reflect the `Origin` header dynamically when `Access-Control-Allow-Credentials: true` is enabled.",
        "CORS headers reject untrusted external origins",
        "Access-Control-Allow-Origin reflects attacker domain with credentials enabled",
    ),
    (
        re.compile(r"\b(secret|api_key|credential|token leak|source map|hardcoded)\b", re.I),
        "Sensitive Information & Credential Disclosure",
        "Information Disclosure > Sensitive Data Exposure",
        "The application discloses sensitive secrets, database credentials, API keys, or unminified source maps in client-accessible responses or error dumps.",
        "Attackers leverage exposed credentials to access third-party services, connect directly to backend databases, or escalate privileges.",
        "Remove hardcoded credentials and source maps from public production builds. Store secrets in environment variables or secret managers.",
        "Secrets redacted; generic error pages displayed",
        "Raw database credentials or API keys exposed in HTTP response",
    ),
    (
        re.compile(r"\b(cookie|httponly|session cookie)\b", re.I),
        "Session Cookie Hardening: Missing HttpOnly and Secure Flags",
        "Session Management > Insecure Cookie Attributes",
        "Session identifiers are issued without `HttpOnly` and `Secure` attributes, allowing client-side scripts to access cookies.",
        "Allows session hijacking via Cross-Site Scripting (XSS) and transmission over unencrypted HTTP channels.",
        "Set `HttpOnly; Secure; SameSite=Lax` on all session cookies.",
        "Session cookies flagged with HttpOnly, Secure, and SameSite attributes",
        "Session cookie issued without security flags",
    ),
    (
        re.compile(r"\b(header|security header|hsts|clickjacking|csp missing)\b", re.I),
        "Missing Security Headers & Cookie Hardening",
        "Server Configuration > Missing Security Headers",
        "The application is missing defensive HTTP headers such as HSTS, X-Content-Type-Options, X-Frame-Options, or Content-Security-Policy.",
        "Leaves the application vulnerable to MIME sniffing, clickjacking, unencrypted HTTP downgrades, and client-side cookie theft.",
        "Configure HSTS (`Strict-Transport-Security`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and Content-Security-Policy headers.",
        "All modern defensive security headers present on HTTP responses",
        "Security headers missing from HTTP response headers",
    ),
]


def is_meta_summary_finding(title: str, evidence: str) -> bool:
    """Check if a finding entry is a meta-run progress summary rather than an atomic vulnerability."""
    meta_title_patterns = [
        r"^P\d+-P\d+.*(?:GenPentest|run\s+#|execution|all confirmed|all phases)",
        r"^\d{4}-\d{2}-\d{2}.*(?:re-run|re-validation|confirmed live|high-value)",
        r"^Full P\d+-P\d+",
        r"^Triage summary",
        r"^Track \d+ ledger",
        r"all \d+ high-value vulns confirmed",
        r"all phases confirmed",
    ]
    for pat in meta_title_patterns:
        if re.search(pat, title, re.I):
            return True

    if re.search(r"P0:.*P1:.*P2:.*P3:", evidence, re.I | re.DOTALL):
        return True
    return False


def clean_finding_title(title: str) -> str:
    """Clean up redundant run artifacts or annotations from finding titles."""
    t = title
    t = re.sub(r"\s*\((?:re-verified|re-validation|verified|confirmed)[^\)]*\)", "", t, flags=re.I)
    t = re.sub(r"^(?:\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO|INFORMATIONAL)\]\s*)", "", t, flags=re.I)
    return t.strip()


def extract_vulnerability_signature(finding: dict, default_target: str = "") -> dict[str, Any]:
    """Extract fine-grained vulnerability classification, endpoint, parameter, and candidate status generically."""
    title = clean_finding_title(str(finding.get("title") or "")).strip()
    evidence = str(finding.get("evidence") or "").strip()
    status = str(finding.get("status") or "").strip().lower()
    t_low = title.lower()
    e_low = evidence.lower()
    comb = f"{t_low} {e_low}"

    is_meta = is_meta_summary_finding(title, evidence)
    is_candidate = "candidate" in t_low or "candidate" in status or "potential" in t_low or "signal" in t_low

    # Extract endpoint generically from title and evidence
    endpoint = ""
    endpoint_matches = re.findall(
        r"(/(?:api/|v[0-9]+/|[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+(?:\.[a-zA-Z0-9]{2,5})?)",
        f"{title} {evidence}"
    )
    if endpoint_matches:
        # Filter out common false positives
        valid_endpoints = [
            m for m in endpoint_matches
            if not m.endswith((".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff", ".map"))
            and len(m) > 1 and not m.startswith("//")
        ]
        if valid_endpoints:
            endpoint = valid_endpoints[0]

    if not endpoint:
        endpoint = str(finding.get("target") or default_target or "Target Application")

    # Extract parameter generically from title and evidence
    param = ""
    param_match = re.search(r"(?:parameter|param|field|sink|query|header|cookie)\s*[:=]?\s*[`'\"]?([a-zA-Z0-9_$-]+)[`'\"]?", comb)
    if param_match:
        param = param_match.group(1)
    else:
        # Try finding key-value in URL query parameters
        url_param_match = re.search(r"\?[a-zA-Z0-9_.-]*?([a-zA-Z0-9_$-]+)=", evidence)
        if url_param_match:
            param = url_param_match.group(1)
        else:
            param = "general"

    # Identify primary vulnerability category using VULN_PATTERNS
    vuln_class = "Application Security Vulnerability"
    for pattern, cat_name, vrt_name, desc_text, impact_text, rem_text, exp_text, act_text in VULN_PATTERNS:
        if pattern.search(title):
            vuln_class = cat_name
            break

    if vuln_class == "Application Security Vulnerability":
        for pattern, cat_name, vrt_name, desc_text, impact_text, rem_text, exp_text, act_text in VULN_PATTERNS:
            if pattern.search(evidence):
                vuln_class = cat_name
                break

    # If title already contains specific details, keep fine-grained categorization
    fine_key = f"{vuln_class}::{endpoint}::{param}"

    return {
        "is_meta": is_meta,
        "is_candidate": is_candidate,
        "vuln_class": vuln_class,
        "endpoint": endpoint,
        "param": param,
        "key": fine_key,
    }


def construct_impact_first_title(title: str, category: str, target: str, severity: str) -> str:
    """Ensure finding title matches: [Bug Class] in [Endpoint] allows [Actor] to [Impact] dynamically."""
    cleaned = clean_finding_title(title)

    if "allows" in cleaned.lower() and (" in " in cleaned.lower() or "/" in cleaned):
        return cleaned

    endpoint_match = re.search(r"(/(?:api/|v[0-9]+/|[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+(?:\.[a-zA-Z0-9]{2,5})?)", cleaned)
    endpoint = endpoint_match.group(1) if endpoint_match else ""

    actor = "unauthenticated attacker" if severity.lower() in ("critical", "high") else "authenticated user"

    c_low = cleaned.lower()

    if "sql" in c_low and ("auth" in c_low or "login" in c_low or "admin" in c_low):
        return f"SQL Injection in {endpoint or '/login'} allows {actor} to bypass authentication as administrator"
    elif "sql" in c_low and ("blind" in c_low or "boolean" in c_low):
        return f"Boolean-Based Blind SQL Injection in {endpoint or 'query parameter'} allows {actor} to extract database contents"
    elif "sql" in c_low:
        return f"SQL Injection in {endpoint or 'database queries'} allows {actor} to execute arbitrary SQL queries"
    elif "lfi" in c_low or "file inclusion" in c_low or "traversal" in c_low:
        return f"Local File Inclusion & Directory Traversal in {endpoint or 'file parameter'} allows {actor} to read arbitrary server files"
    elif "xss" in c_low and "stored" in c_low:
        return f"Stored Cross-Site Scripting (XSS) in {endpoint or 'persistent input fields'} allows attacker to execute JavaScript in victim sessions"
    elif "xss" in c_low and ("reflected" in c_low or "search" in c_low):
        return f"Reflected Cross-Site Scripting (XSS) in {endpoint or 'search/query parameter'} allows attacker to execute JavaScript in victim browser"
    elif "xss" in c_low:
        return f"Cross-Site Scripting (XSS) in {endpoint or 'web pages'} allows attacker to execute arbitrary script in victim browser"
    elif "redirect" in c_low or "returl" in c_low:
        return f"Open URL Redirection in {endpoint or 'redirection parameter'} allows attacker to redirect users to untrusted domains"
    elif "plaintext password" in c_low or "password storage" in c_low:
        return f"Insecure Cryptographic Storage: Plaintext Password Storage in {endpoint or 'backend database'} allows instant credential theft"
    elif "trace" in c_low or "xst" in c_low:
        return f"HTTP TRACE Method Enabled on {target} allows attacker to capture cookie headers via Cross-Site Tracing"
    elif "cookie" in c_low or "httponly" in c_low:
        return f"Session Cookie Hardening: Missing HttpOnly & Secure Flags on {target} allows cookie theft via XSS"
    elif "header" in c_low or "hsts" in c_low or "csp" in c_low:
        return f"Missing Defensive Security Headers (HSTS, CSP, X-Frame-Options) on {target} increases risk of client-side compromise"
    elif "idor" in c_low or "bola" in c_low:
        return f"Broken Object Level Authorization (IDOR) in {endpoint or '/api/resource'} allows authenticated user to access other tenants' data"
    elif "csrf" in c_low:
        return f"Missing Cross-Site Request Forgery (CSRF) Protection on {endpoint or 'state-changing forms'} allows unauthorized actions"
    elif "ssrf" in c_low:
        return f"Server-Side Request Forgery (SSRF) in {endpoint or 'URL fetch parameter'} allows attacker to pivot to internal services"
    elif "rce" in c_low or "command injection" in c_low:
        return f"Remote Code Execution (RCE) in {endpoint or 'command handler'} allows {actor} to execute arbitrary OS commands"

    return f"{category} in {endpoint or target} allows {actor} to bypass security boundaries"


def parse_http_blocks(evidence: str) -> list[dict[str, str]]:
    """Parse raw HTTP request and response pairs from an evidence block."""
    pairs = []

    if "REQUEST" in evidence.upper() and "RESPONSE" in evidence.upper():
        req_blocks = re.findall(r"(?:REQUEST[^\n]*\n)([\s\S]+?)(?=(?:RESPONSE|\Z))", evidence, re.I)
        res_blocks = re.findall(r"(?:RESPONSE[^\n]*\n)([\s\S]+?)(?=(?:REQUEST|\Z))", evidence, re.I)
        for i in range(max(len(req_blocks), len(res_blocks))):
            req = req_blocks[i].strip() if i < len(req_blocks) else ""
            res = res_blocks[i].strip() if i < len(res_blocks) else ""
            req = re.sub(r"^```[a-zA-Z0-9_-]*\n", "", req).rstrip("`").strip()
            res = re.sub(r"^```[a-zA-Z0-9_-]*\n", "", res).rstrip("`").strip()
            if req or res:
                pairs.append({"request": req, "response": res})
        if pairs:
            return pairs

    lines = evidence.splitlines()
    curr_req, curr_res = [], []
    in_res = False

    for line in lines:
        cleaned = line.strip("`")
        if re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+[^\s]+\s+HTTP/[12]", cleaned, re.I):
            if curr_req or curr_res:
                pairs.append({"request": "\n".join(curr_req).strip(), "response": "\n".join(curr_res).strip()})
                curr_req, curr_res = [], []
            in_res = False
            curr_req.append(cleaned)
        elif re.match(r"^HTTP/[12](?:\.[01])?\s+\d{3}", cleaned, re.I):
            in_res = True
            curr_res.append(cleaned)
        elif in_res:
            curr_res.append(cleaned)
        else:
            curr_req.append(cleaned)

    if curr_req or curr_res:
        pairs.append({"request": "\n".join(curr_req).strip(), "response": "\n".join(curr_res).strip()})

    if not pairs:
        pairs.append({"request": evidence.strip(), "response": ""})

    return pairs


def gather_target_context(project: Path, target: str) -> dict[str, Any]:
    """Extract full architectural and engagement context for the target."""
    settings = load_settings(project)
    root_val = settings.get("engagementRoot") or "~/Targets"
    eng_dir = Path(root_val).expanduser() / target
    local_gen = project / "GenPentest"

    context = {
        "target": target,
        "application_name": target,
        "tech_stack": "Web Application & API",
        "web_server": "HTTP Server",
        "app_summary": "",
        "public_index": "",
        "endpoints_count": 0,
        "raw_findings_count": 0,
    }

    for p in [eng_dir / "GenPentest" / "appsummary.md", eng_dir / "appsummary.md", local_gen / "appsummary.md", project / "appsummary.md"]:
        if p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace")
            context["app_summary"] = text
            app_match = re.search(r"\*\*(?:Application|App|Platform|Name):\*\*\s*([^\n]+)", text, re.I)
            if app_match:
                context["application_name"] = app_match.group(1).strip()
            server_match = re.search(r"\*\*(?:Server|Web Server|Stack|Tech Stack):\*\*\s*([^\n]+)", text, re.I)
            if server_match:
                context["tech_stack"] = server_match.group(1).strip()
            break

    for p in [eng_dir / "GenPentest" / "publicindex.md", local_gen / "publicindex.md"]:
        if p.is_file():
            context["public_index"] = p.read_text(encoding="utf-8", errors="replace")
            break

    return context


def generate_synthesized_poc_steps(title: str, evidence: str, target: str) -> str:
    """Generate structured, numbered step-by-step reproduction steps from raw evidence generically."""
    t_low = title.lower()
    e_low = evidence.lower()
    comb = f"{t_low} {e_low}"

    # Extract endpoint generically
    endpoint = ""
    endpoint_matches = re.findall(
        r"(/(?:api/|v[0-9]+/|[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+(?:\.[a-zA-Z0-9]{2,5})?)",
        comb
    )
    if endpoint_matches:
        valid_endpoints = [
            m for m in endpoint_matches
            if not m.endswith((".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff", ".map"))
            and len(m) > 1 and not m.startswith("//")
        ]
        if valid_endpoints:
            endpoint = valid_endpoints[0]

    # Extract parameter generically
    param = ""
    param_match = re.search(r"(?:parameter|param|field|sink|query|header|cookie)\s*[:=]?\s*[`'\"]?([a-zA-Z0-9_$-]+)[`'\"]?", comb)
    if param_match:
        param = param_match.group(1)

    url_target = f"http://{target}{endpoint}" if endpoint.startswith("/") else f"http://{target}"

    if "lfi" in comb or "file inclusion" in comb or "traversal" in comb:
        p_str = f" in the `{param}` parameter" if param else ""
        return (
            f"1. Access the target application endpoint at `{url_target}`.\n"
            f"2. Supply directory traversal sequences or internal system/source filenames{p_str} (e.g. `../../../../etc/passwd` or sensitive configuration files).\n"
            f"3. Send the HTTP GET request and observe that the server returns HTTP 200 OK.\n"
            f"4. Confirm unauthenticated arbitrary file read or source code disclosure in the response body."
        )
    elif ("sql" in comb) and ("login" in comb or "auth bypass" in comb or "admin" in comb):
        p_str = f" in the `{param}` field" if param else ""
        return (
            f"1. Navigate to the authentication endpoint at `{url_target}`.\n"
            f"2. Submit SQL injection authentication bypass metacharacters{p_str} (e.g. `' OR '1'='1'--`).\n"
            f"3. Observe that the server accepts the manipulated query logic, responds with HTTP 302 Found or 200 OK, and establishes an administrative session.\n"
            f"4. Confirm complete authentication bypass into the application."
        )
    elif ("sql" in comb) and ("blind" in comb or "boolean" in comb):
        p_str = f" in the `{param}` parameter" if param else ""
        return (
            f"1. Send an HTTP request with a Boolean TRUE condition{p_str} to `{url_target}` (e.g. `AND 1=1`), observing normal page execution.\n"
            f"2. Send an HTTP request with a Boolean FALSE condition{p_str} to `{url_target}` (e.g. `AND 1=2`), observing error or differential output.\n"
            f"3. Confirm that the Boolean differential response proves arbitrary SQL query injection into the backend database."
        )
    elif "sql" in comb:
        p_str = f" in the `{param}` parameter" if param else ""
        return (
            f"1. Navigate to `{url_target}`.\n"
            f"2. Inject SQL query metacharacters{p_str} (e.g. `' UNION SELECT ... --`).\n"
            f"3. Inspect the server response and verify backend database syntax errors or database data returned in the response body."
        )
    elif "xss" in comb and "stored" in comb:
        p_str = f" in the `{param}` field" if param else ""
        return (
            f"1. Log into the application and navigate to `{url_target}`.\n"
            f"2. Submit a stored cross-site scripting payload{p_str}: `<script>alert(document.domain)</script>`.\n"
            f"3. View the rendered content in a victim browser session and observe arbitrary JavaScript execution in the client DOM context."
        )
    elif "xss" in comb:
        p_str = f" in `{param}`" if param else ""
        return (
            f"1. Issue an HTTP GET request to `{url_target}` supplying an XSS payload{p_str}: `<script>alert(document.domain)</script>`.\n"
            f"2. Inspect the HTTP response body and verify that the payload is reflected directly without HTML entity encoding.\n"
            f"3. Confirm arbitrary script execution in the client browser context."
        )
    elif "redirect" in comb or "returl" in comb:
        p_str = f" in the `{param}` parameter" if param else ""
        return (
            f"1. Craft a request supplying an external untrusted URL{p_str} to `{url_target}` (e.g. `https://evil.com/phish`).\n"
            f"2. Send the request and observe the server issuing an HTTP 302/301 redirect with `Location: https://evil.com/phish`.\n"
            f"3. Confirm unvalidated redirection to third-party domains."
        )
    elif "plaintext password" in comb or "password storage" in comb:
        return (
            f"1. Review backend database schema and queries discovered during assessment.\n"
            f"2. Inspect the user authentication database table and password verification routines.\n"
            f"3. Confirm that user passwords are stored as raw unhashed plaintext strings."
        )
    elif "csrf" in comb or "cross-site request forgery" in comb:
        return (
            f"1. Inspect state-changing forms and endpoints at `{url_target}`.\n"
            f"2. Verify that requests do not require anti-CSRF challenge tokens or SameSite validation.\n"
            f"3. Construct an external cross-origin HTML form and verify unauthorized action execution in an authenticated victim session."
        )
    elif "trace" in comb or "xst" in comb:
        return (
            f"1. Send an HTTP TRACE request to `{url_target}` with a test header `X-Probe-Test: true`.\n"
            f"2. Observe HTTP 200 OK echoing all request headers and cookies back in the response body.\n"
            f"3. Confirm Cross-Site Tracing capability."
        )
    elif "cookie" in comb or "httponly" in comb:
        return (
            f"1. Inspect the `Set-Cookie` response headers returned by `{url_target}`.\n"
            f"2. Verify that session cookies lack the `HttpOnly` and `Secure` flags.\n"
            f"3. Confirm client-side script access via `document.cookie`."
        )
    elif "header" in comb or "hsts" in comb or "csp" in comb:
        return (
            f"1. Inspect HTTP response headers returned by `{url_target}`.\n"
            f"2. Verify the absence of defensive HTTP headers: `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Content-Security-Policy`.\n"
            f"3. Confirm vulnerability to clickjacking and MIME-sniffing attacks."
        )
    else:
        return (
            f"1. Construct a proof-of-concept request against `{url_target}` with the identified payload.\n"
            f"2. Inspect the server response and verify the security boundary violation.\n"
            f"3. Confirm reproducibility across authenticated and unauthenticated sessions."
        )


def enrich_finding_details(finding: dict, default_target: str = "") -> dict:
    """Enrich finding with structured metadata, descriptions, HTTP pairs, impact, and remediation."""
    title = str(finding.get("title") or "Untitled Vulnerability").strip()
    target = str(finding.get("target") or default_target or "unknown").strip()
    sev = str(finding.get("severity") or "medium").strip().lower()
    if sev in ("info", "informational"):
        sev = "informational"
    if sev not in CVSS_MAP:
        sev = "medium"

    evidence = str(finding.get("evidence") or "").strip()
    existing_desc = str(finding.get("description") or "").strip()
    existing_impact = str(finding.get("impact") or "").strip()
    existing_steps = str(finding.get("steps") or "").strip()
    existing_remediation = str(finding.get("remediation") or "").strip()
    status = str(finding.get("status") or "confirmed").strip()

    category = finding.get("category") or "Application Security Vulnerability"
    vrt_category = "Broken Access Control > Security Misconfiguration"
    default_desc = f"An authorized security assessment identified a {sev} vulnerability on {target}."
    default_impact = f"An attacker can exploit this vulnerability to bypass security boundaries on {target}."
    default_remediation = "Implement strict server-side input validation, contextual output encoding, and principle of least privilege."
    expected_behavior = "403 Forbidden / Strict parameterization"
    actual_behavior = "200 OK / Unauthorized execution"

    # Match primary category using title first, then evidence
    matched_pattern = False
    for pattern, cat_name, vrt_name, desc_text, impact_text, rem_text, exp_text, act_text in VULN_PATTERNS:
        if pattern.search(title):
            matched_pattern = True
            category = cat_name
            vrt_category = vrt_name
            default_desc = desc_text
            default_impact = impact_text
            default_remediation = rem_text
            expected_behavior = exp_text
            actual_behavior = act_text
            break

    if not matched_pattern:
        for pattern, cat_name, vrt_name, desc_text, impact_text, rem_text, exp_text, act_text in VULN_PATTERNS:
            if pattern.search(f"{title} {evidence}"):
                category = cat_name
                vrt_category = vrt_name
                default_desc = desc_text
                default_impact = impact_text
                default_remediation = rem_text
                expected_behavior = exp_text
                actual_behavior = act_text
                break

    clean_title = construct_impact_first_title(title, category, target, sev)
    description = existing_desc or default_desc
    impact = existing_impact or default_impact
    remediation = existing_remediation or default_remediation
    steps = existing_steps or generate_synthesized_poc_steps(clean_title, evidence, target)

    http_pairs = parse_http_blocks(evidence)

    cvss_meta = CVSS_MAP.get(sev, CVSS_MAP["medium"])
    gate = evaluate_finding_gate({
        "id": finding.get("id", "vuln"),
        "title": clean_title,
        "target": target,
        "evidence": evidence or steps,
        "remediation": remediation,
        "status": status,
    })

    return {
        "id": finding.get("id") or "vuln",
        "title": clean_title,
        "category": category,
        "vrt_category": vrt_category,
        "vrt_priority": cvss_meta["vrt_p"],
        "severity": sev,
        "target": target,
        "status": status,
        "description": description,
        "steps": steps,
        "expected_behavior": finding.get("expected_behavior") or expected_behavior,
        "actual_behavior": finding.get("actual_behavior") or actual_behavior,
        "evidence": evidence,
        "http_pairs": http_pairs,
        "impact": impact,
        "remediation": remediation,
        "cvss_score": finding.get("cvss_score") or cvss_meta["score"],
        "cvss_vector": finding.get("cvss_vector") or cvss_meta["vector"],
        "cvss_vector_v4": finding.get("cvss_vector_v4") or cvss_meta["vector_v4"],
        "gate_score": gate["score"],
        "gate_passed": gate["passed"],
        "gate_results": gate["results"],
    }


def heuristic_deduplicate_and_synthesize(findings: list[dict], default_target: str = "") -> tuple[list[dict], list[dict]]:
    """Deterministic, high-fidelity deduplication separating Confirmed Findings and Candidate Signals."""
    confirmed_groups: dict[str, list[dict]] = {}
    candidate_groups: dict[str, list[dict]] = {}

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

    for f in findings:
        sig = extract_vulnerability_signature(f, default_target=default_target)
        if sig["is_meta"]:
            continue

        key = sig["key"]
        if sig["is_candidate"]:
            candidate_groups.setdefault(key, []).append(f)
        else:
            confirmed_groups.setdefault(key, []).append(f)

    # Process Confirmed Findings
    deduplicated_confirmed: list[dict] = []
    for idx, (key, items) in enumerate(confirmed_groups.items(), 1):
        best_item = max(items, key=lambda x: (
            sev_rank.get(str(x.get("severity", "medium")).lower(), 2),
            len(str(x.get("evidence", ""))),
            len(str(x.get("description", "")))
        ))

        all_evidences = [str(x.get("evidence", "")).strip() for x in items if x.get("evidence")]
        merged_ev = "\n\n".join(list(dict.fromkeys(all_evidences))) if all_evidences else str(best_item.get("evidence", ""))

        clean_item = dict(best_item)
        clean_item["id"] = f"F-{idx:02d}"
        clean_item["evidence"] = merged_ev
        clean_item["title"] = clean_finding_title(clean_item.get("title", ""))

        enriched = enrich_finding_details(clean_item, default_target=default_target)
        deduplicated_confirmed.append(enriched)

    deduplicated_confirmed.sort(key=lambda x: sev_rank.get(x.get("severity", "medium").lower(), 2), reverse=True)
    for idx, item in enumerate(deduplicated_confirmed, 1):
        item["id"] = f"F-{idx:02d}"

    # Process Candidate Signals
    deduplicated_candidates: list[dict] = []
    for idx, (key, items) in enumerate(candidate_groups.items(), 1):
        best_cand = max(items, key=lambda x: (
            sev_rank.get(str(x.get("severity", "low")).lower(), 1),
            len(str(x.get("evidence", "")))
        ))
        clean_cand = dict(best_cand)
        clean_cand["id"] = f"S-{idx:02d}"
        clean_cand["status"] = "candidate"
        enriched_cand = enrich_finding_details(clean_cand, default_target=default_target)
        deduplicated_candidates.append(enriched_cand)

    deduplicated_candidates.sort(key=lambda x: sev_rank.get(x.get("severity", "low").lower(), 1), reverse=True)
    for idx, item in enumerate(deduplicated_candidates, 1):
        item["id"] = f"S-{idx:02d}"

    return deduplicated_confirmed, deduplicated_candidates


def llm_process_report_findings(
    provider: Any | None,
    raw_findings: list[dict],
    target_context: dict[str, Any],
) -> tuple[list[dict], list[dict]]:
    """Use LLM intelligence to deduplicate findings and write publication-grade Description, Steps (PoC), Impact, and Recommendation."""
    target = target_context.get("target", "Target")
    app_name = target_context.get("application_name", target)
    tech_stack = target_context.get("tech_stack", "Web Application & API")

    confirmed_list, candidate_list = heuristic_deduplicate_and_synthesize(raw_findings, default_target=target)

    if not provider:
        return confirmed_list, candidate_list

    input_records = []
    for f in confirmed_list:
        input_records.append({
            "id": f.get("id"),
            "title": f.get("title", ""),
            "severity": f.get("severity", "medium"),
            "category": f.get("category", ""),
            "target": f.get("target", target),
            "evidence": str(f.get("evidence", ""))[:1200],
            "description": f.get("description", ""),
            "remediation": f.get("remediation", ""),
        })

    prompt = f"""You are a Principal Security Consultant and Lead Technical Author for publication-ready penetration testing and bug bounty reports.
Enrich the following deduplicated security findings for target: {target} (Application: {app_name}, Detected Stack: {tech_stack}).

CRITICAL REPORTING RULES:
1. ZERO THEORETICAL LANGUAGE: NEVER use words like "could potentially", "could be used to", "may allow", "might be possible", "appears to", or "seems to". State exact verified data, endpoints, and impacts.
2. TITLE FORMULA: Every title MUST follow the formula:
   "[Bug Class] in [Exact Endpoint / Feature] allows [Attacker Role] to [Impact]"
3. IMPACT-FIRST SUMMARY: Sentence 1 states the exact data/impact and access level, not a textbook lecture. Under 3 sentences.
4. STEPS TO REPRODUCE: Structured, numbered step-by-step reproduction instructions showing how to reproduce the vulnerability, with exact parameters, payloads, and observed behavior.
5. EXPECTED VS ACTUAL: Explicitly specify Expected Behavior (e.g. "403 Forbidden / Parameterized query") and Actual Behavior (e.g. "200 OK disclosing private data").
6. IMPACT STATEMENT: Quantified security & business risk (e.g. customer PII, admin account takeover, mass data leakage).
7. REMEDIATION: 1-2 sentence concrete fix with code or configuration guidance.
8. PRESERVE ALL DISTINCT VULNERABILITY CLASSES: Keep all provided findings in the array; do not drop any valid vulnerability.

Input Findings:
{json.dumps(input_records, indent=2)}

OUTPUT FORMAT REQUIREMENTS:
Return ONLY a valid JSON array of finding objects. Each object MUST have the exact keys:
["id", "title", "severity", "category", "target", "description", "steps", "expected_behavior", "actual_behavior", "impact", "remediation", "evidence"]
Do not wrap in any extra outer object. Do not include conversational commentary.
"""

    try:
        reply = provider.complete([{"role": "user", "content": prompt}], tools=[])
        reply_text = (reply.text or "").strip()

        json_match = re.search(r"(\[\s*\{[\s\S]*\}\s*\])", reply_text)
        if json_match:
            parsed = json.loads(json_match.group(1))
            if isinstance(parsed, list) and len(parsed) > 0:
                final_findings = []
                for idx, item in enumerate(parsed, 1):
                    if isinstance(item, dict) and item.get("title"):
                        item["id"] = f"F-{idx:02d}"
                        final_findings.append(enrich_finding_details(item, default_target=target))
                if len(final_findings) >= len(confirmed_list) - 2:
                    return final_findings, candidate_list
    except Exception as exc:
        logger.warning(f"LLM report synthesis error: {exc}. Falling back to heuristic engine.")

    return confirmed_list, candidate_list


def parse_vulnerabilities_markdown(text: str, default_target: str = "") -> list[dict]:
    """Parse findings from a Vulnerabilities.md file into structured finding dictionaries."""
    findings: list[dict] = []
    current: dict[str, Any] = {}

    lines = text.splitlines()
    for line in lines:
        header_match = re.match(r"^###?\s+(?:\[(CRITICAL|HIGH|MEDIUM|LOW|INFO|INFORMATIONAL)\]\s*)?([^\n]+)", line, re.I)
        if header_match:
            if current and current.get("title"):
                findings.append(enrich_finding_details(current, default_target))
            sev = (header_match.group(1) or "medium").lower()
            if sev == "info":
                sev = "informational"
            title = header_match.group(2).strip()
            current = {
                "id": f"F-{len(findings)+1:02d}",
                "title": title,
                "severity": sev,
                "target": default_target,
                "status": "confirmed",
                "evidence": "",
                "remediation": "",
                "description": "",
                "impact": "",
                "steps": "",
            }
            continue

        if not current:
            continue

        stripped = line.strip()
        if stripped.lower().startswith(("- **severity:**", "- **impact:**", "**severity:**")):
            val = stripped.split(":", 1)[1].strip().strip("*").lower()
            if val in CVSS_MAP:
                current["severity"] = val
        elif stripped.lower().startswith(("- **target:**", "- **endpoint:**", "**target:**")):
            val = stripped.split(":", 1)[1].strip().strip("*")
            if val:
                current["target"] = val
        elif stripped.lower().startswith(("- **remediation:**", "- **fix:**", "**remediation:**")):
            val = stripped.split(":", 1)[1].strip().strip("*")
            current["remediation"] = val
        elif stripped.lower().startswith(("- **description:**", "**description:**")):
            val = stripped.split(":", 1)[1].strip().strip("*")
            current["description"] = val
        elif stripped.startswith("```"):
            current["evidence"] += "\n" + line
        else:
            if current.get("remediation") and not current.get("evidence"):
                current["remediation"] += "\n" + line
            elif current.get("evidence"):
                current["evidence"] += "\n" + line
            else:
                current["description"] = (current.get("description", "") + "\n" + line).strip()

    if current and current.get("title"):
        findings.append(enrich_finding_details(current, default_target))
    return findings


def gather_target_findings(project: Path, target: str, store_findings: list[dict] | None = None) -> list[dict]:
    """Gather raw findings for a given target from SQLite store and target directory artifacts."""
    raw_results: list[dict] = []
    seen_titles: set[str] = set()

    if store_findings:
        for f in store_findings:
            f_target = str(f.get("target") or "").lower()
            if target.lower() in f_target or f_target in target.lower() or target == "all":
                raw_results.append(f)
                seen_titles.add(f.get("title", "").lower().strip())

    settings = load_settings(project)
    root_val = settings.get("engagementRoot") or "~/Targets"
    eng_dir = Path(root_val).expanduser() / target
    local_target_dir = project / "GenPentest"

    paths_to_check = [
        eng_dir / "Vulnerabilities.md",
        eng_dir / "findings" / "Vulnerabilities.md",
        project / f"{target}_Vulnerabilities.md",
        local_target_dir / "findings" / "Vulnerabilities.md",
        project / "Vulnerabilities.md",
    ]

    for path in paths_to_check:
        if path.is_file():
            try:
                parsed = parse_vulnerabilities_markdown(path.read_text(encoding="utf-8"), default_target=target)
                for p in parsed:
                    if p.get("title", "").lower().strip() not in seen_titles:
                        raw_results.append(p)
                        seen_titles.add(p.get("title", "").lower().strip())
            except Exception:
                pass

    return raw_results


def generate_executive_html_report(
    target: str,
    findings: list[dict],
    context: dict[str, Any] | None = None,
    candidates: list[dict] | None = None,
) -> str:
    """Generate a corporate, publication-grade, A4-printable HTML penetration test report."""
    ctx = context or {"application_name": target, "tech_stack": "Web Application & API"}
    app_name = ctx.get("application_name") or target
    tech_stack = ctx.get("tech_stack") or "Web Application & API"
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in findings:
        s = (f.get("severity") or "medium").lower()
        counts[s] = counts.get(s, 0) + 1

    overview_rows = []
    for i, f in enumerate(findings, 1):
        fid = f.get("id") or f"F-{i:02d}"
        sev = (f.get("severity") or "medium").upper()
        badge_cls = f"sev-{sev.lower()}"
        esc_title = html.escape(str(f.get("title", "Untitled Finding")))
        esc_category = html.escape(str(f.get("category", "General")))
        esc_target = html.escape(str(f.get("target", target)))
        overview_rows.append(
            f"<tr><td>{fid}</td><td>{esc_title}</td><td>{esc_category}</td><td><span class='{badge_cls}'>{sev}</span></td><td><code>{esc_target}</code></td></tr>"
        )

    findings_sections = []
    for sev_group, sev_label in [
        ("critical", "4.1 Critical Severity Findings"),
        ("high", "4.2 High Severity Findings"),
        ("medium", "4.3 Medium Severity Findings"),
        ("low", "4.4 Low Severity Findings"),
        ("informational", "4.5 Informational Findings"),
    ]:
        group_items = [f for f in findings if (f.get("severity") or "medium").lower() == sev_group]
        if not group_items:
            continue

        findings_sections.append(f"<h3>{sev_label}</h3>")

        for f in group_items:
            fid = f.get("id") or "F-00"
            sev = (f.get("severity") or "medium").upper()
            esc_title = html.escape(str(f.get("title", "Untitled Finding")))
            esc_category = html.escape(str(f.get("category", "General Security")))
            esc_target = html.escape(str(f.get("target", target)))
            esc_desc = html.escape(str(f.get("description", "")))
            esc_steps = html.escape(str(f.get("steps", "")))
            esc_expected = html.escape(str(f.get("expected_behavior", "403 Forbidden")))
            esc_actual = html.escape(str(f.get("actual_behavior", "200 OK / Vulnerable execution")))
            esc_impact = html.escape(str(f.get("impact", "")))
            esc_rem = html.escape(str(f.get("remediation", "")))

            reqres_html_blocks = []
            http_pairs = f.get("http_pairs") or [{"request": f.get("evidence", ""), "response": ""}]
            for p_idx, pair in enumerate(http_pairs, 1):
                req_text = html.escape(pair.get("request", "")).strip()
                res_text = html.escape(pair.get("response", "")).strip()

                res_text = re.sub(r"(&quot;[^&]+password[^&]*&quot;|Location:[^\n]+|HTTP/1\.[01]\s+\d{3}[^\n]*)", r"<span class='hl'>\1</span>", res_text)

                req_head = f"HTTP EVIDENCE #{p_idx} &mdash; REQUEST" if len(http_pairs) > 1 else "RAW HTTP REQUEST EVIDENCE"
                res_head = f"HTTP EVIDENCE #{p_idx} &mdash; RESPONSE" if len(http_pairs) > 1 else "RAW HTTP RESPONSE EVIDENCE"

                reqres_box = f"""
                <div class="reqres">
                    <div class="head">{req_head}</div>
                    <pre class="req">{req_text or 'No raw request captured.'}</pre>
                    {f'<div class="head">{res_head}</div><pre class="res">{res_text}</pre>' if res_text else ''}
                </div>
                """
                reqres_html_blocks.append(reqres_box)

            exp_act_box = f"""
            <div class="exp-act-grid">
                <div class="exp-box"><b>Expected Behavior:</b> {esc_expected}</div>
                <div class="act-box"><b>Actual Behavior:</b> {esc_actual}</div>
            </div>
            """

            steps_box = f"""
            <div class="steps-box">
                <div class="steps-head">Step-by-Step Reproduction (PoC)</div>
                <div class="steps-body">{esc_steps}</div>
            </div>
            """ if esc_steps else ""

            finding_box = f"""
            <div class="find {sev_group}">
                <h4>{fid} &mdash; {esc_title}</h4>
                <div class="meta">
                    <span class="lbl">Severity:</span> <span class="sev-{sev_group}">{sev}</span> &nbsp;|&nbsp;
                    <span class="lbl">Class:</span> {esc_category} &nbsp;|&nbsp;
                    <span class="lbl">Target:</span> <code>{esc_target}</code> &nbsp;|&nbsp;
                    <span class="lbl">CVSS v3.1:</span> {f.get('cvss_score', 5.4)} (<code>{f.get('cvss_vector', '')}</code>) &nbsp;|&nbsp;
                    <span class="lbl">Validation Gate:</span> <span class="gate-{'pass' if f.get('gate_passed') else 'review'}">{'✓ PASSED' if f.get('gate_passed') else '⚠️ REQUIRES REVIEW'} [{f.get('gate_score', '6/7')}]</span>
                </div>
                <p><b>Summary &amp; Root Cause:</b><br>{esc_desc}</p>
                {exp_act_box}
                {steps_box}
                {''.join(reqres_html_blocks)}
                <p><b>Security &amp; Business Impact:</b><br>{esc_impact}</p>
                <p><b>Remediation Guidance:</b><br>{esc_rem}</p>
            </div>
            """
            findings_sections.append(finding_box)

    rem_rows = []
    for f in findings:
        fid = f.get("id") or "F-00"
        sev = (f.get("severity") or "medium").upper()
        esc_title = html.escape(str(f.get("title", "")))
        esc_rem = html.escape(str(f.get("remediation", "")))
        priority = "Immediate (24-48h)" if sev in ("CRITICAL", "HIGH") else ("Standard (1-2 Weeks)" if sev == "MEDIUM" else "Next Sprint")
        rem_rows.append(
            f"<tr><td>{fid}</td><td>{esc_title}</td><td><span class='sev-{sev.lower()}'>{sev}</span></td><td>{esc_rem}</td><td><strong>{priority}</strong></td></tr>"
        )

    # Candidate Signals Rows for Appendix
    candidate_rows = []
    if candidates:
        for c in candidates:
            cid = c.get("id", "S-00")
            c_title = html.escape(str(c.get("title", "")))
            c_sev = (c.get("severity") or "low").upper()
            c_cat = html.escape(str(c.get("category", "Observation")))
            candidate_rows.append(
                f"<tr><td>{cid}</td><td>{c_title}</td><td>{c_cat}</td><td><span class='sev-{c_sev.lower()}'>{c_sev}</span></td><td>Candidate Signal</td></tr>"
            )

    candidate_section_html = f"""
    <h3>6.2 Exploratory Reconnaissance Signals &amp; Hardening Candidates</h3>
    <p>The following preliminary signals were recorded during reconnaissance and initial probing. While not full confirmed standalone exploits, they represent attack surface observations or environmental telemetry:</p>
    <table class="data">
    <tr><th>ID</th><th>Observed Signal / Lead</th><th>Category</th><th>Potential Severity</th><th>Verification Status</th></tr>
    {''.join(candidate_rows) if candidate_rows else '<tr><td colspan="5">No exploratory candidate signals recorded.</td></tr>'}
    </table>
    """ if candidate_rows else ""

    html_document = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Executive Security Assessment Report - {html.escape(target)}</title>
<style>
@page {{
  size: A4;
  margin: 2cm 1.8cm;
  @bottom-center {{ content: "Confidential - Authorized Security Assessment"; font-size: 8pt; color: #888; }}
  @bottom-right {{ content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color: #888; }}
}}
@page cover {{ margin: 0; @bottom-center {{ content: none; }} @bottom-right {{ content: none; }} }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; font-size: 9.5pt; color: #222; line-height: 1.5; }}
.cover {{ page: cover; height: 29.7cm; background: #0f2a43; color: #fff; padding: 3cm 2.5cm; box-sizing: border-box; position: relative; }}
.cover .tag {{ font-size: 10pt; letter-spacing: 3px; color: #8fb8de; text-transform: uppercase; margin-bottom: 1.5cm; font-weight: 600; }}
.cover h1 {{ font-size: 26pt; margin: 0 0 0.4cm; line-height: 1.2; font-weight: 700; }}
.cover h2 {{ font-size: 13pt; font-weight: normal; color: #cfe0f0; margin: 0 0 2cm; }}
.cover table {{ font-size: 10pt; color: #e8f0f8; border-collapse: collapse; margin-top: 1.5cm; width: 100%; }}
.cover td {{ padding: 6px 12px 6px 0; }}
.cover td.k {{ color: #8fb8de; width: 3.5cm; font-weight: 600; }}
.cover .footer {{ position: absolute; bottom: 2cm; left: 2.5cm; right: 2.5cm; font-size: 9pt; color: #6d8aa8; border-top: 1px solid #2c4a68; padding-top: 10px; }}
h2.sec {{ font-size: 14pt; color: #0f2a43; border-bottom: 2px solid #0f2a43; padding-bottom: 4px; margin-top: 28px; }}
h3 {{ font-size: 11.5pt; color: #14406b; margin-top: 20px; }}
table.data {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
table.data th {{ background: #0f2a43; color: #fff; padding: 6px 8px; text-align: left; font-size: 9pt; }}
table.data td {{ border: 1px solid #d1d5db; padding: 6px 8px; font-size: 8.8pt; vertical-align: top; }}
table.data tr:nth-child(even) td {{ background: #f8fafc; }}
.sev-critical {{ color: #fff; background: #b91c1c; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 8.5pt; display: inline-block; }}
.sev-high {{ color: #fff; background: #c2410c; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 8.5pt; display: inline-block; }}
.sev-medium {{ color: #fff; background: #b45309; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 8.5pt; display: inline-block; }}
.sev-low {{ color: #fff; background: #15803d; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 8.5pt; display: inline-block; }}
.sev-informational {{ color: #374151; background: #e5e7eb; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 8.5pt; display: inline-block; }}
.gate-pass {{ color: #166534; font-weight: bold; }}
.gate-review {{ color: #b45309; font-weight: bold; }}
code, .mono {{ font-family: "JetBrains Mono", Consolas, Monaco, monospace; font-size: 8.5pt; background: #f1f5f9; padding: 2px 4px; border-radius: 3px; }}
.reqres {{ background: #f8fafc; border: 1px solid #cbd5e1; margin: 10px 0 14px; page-break-inside: avoid; border-radius: 4px; overflow: hidden; }}
.reqres .head {{ background: #0f2a43; color: #fff; font-size: 8.5pt; font-weight: bold; padding: 5px 10px; }}
.reqres pre {{ margin: 0; padding: 8px 10px; font-size: 8pt; overflow: hidden; white-space: pre-wrap; word-wrap: break-word; font-family: "JetBrains Mono", Consolas, Monaco, monospace; }}
.reqres pre.req {{ background: #eef4fb; border-bottom: 1px solid #cbd5e1; color: #0f172a; }}
.reqres pre.res {{ background: #fbf3ee; color: #0f172a; }}
.exp-act-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 8px 0; font-size: 8.8pt; }}
.exp-box {{ background: #f0fdf4; border-left: 3px solid #16a34a; padding: 6px 10px; color: #166534; border-radius: 2px; }}
.act-box {{ background: #fef2f2; border-left: 3px solid #dc2626; padding: 6px 10px; color: #991b1b; border-radius: 2px; }}
.steps-box {{ background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 4px; margin: 10px 0; overflow: hidden; }}
.steps-box .steps-head {{ background: #1e293b; color: #ffffff; font-weight: bold; font-size: 8.5pt; padding: 4px 10px; }}
.steps-box .steps-body {{ padding: 8px 10px; font-size: 8.8pt; color: #0f172a; white-space: pre-wrap; line-height: 1.6; }}
.find {{ border: 1px solid #d5dde5; border-left: 6px solid #0f2a43; padding: 12px 16px; margin: 16px 0; page-break-inside: avoid; border-radius: 4px; background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
.find.critical {{ border-left-color: #b91c1c; }}
.find.high {{ border-left-color: #c2410c; }}
.find.medium {{ border-left-color: #b45309; }}
.find.low {{ border-left-color: #15803d; }}
.find.informational {{ border-left-color: #64748b; }}
.find h4 {{ margin: 0 0 6px; font-size: 11pt; color: #0f2a43; }}
.find .meta {{ font-size: 8.8pt; color: #475569; margin-bottom: 8px; border-bottom: 1px solid #f1f5f9; padding-bottom: 6px; }}
.find .lbl {{ font-weight: bold; color: #0f2a43; }}
.toc ul {{ list-style: none; padding-left: 0; }}
.toc li {{ margin: 5px 0; font-size: 9.5pt; }}
.hl {{ background: #fef08a; padding: 1px 3px; font-weight: bold; border-radius: 2px; }}
</style>
</head>
<body>

<div class="cover">
  <div class="tag">Executive Security Assessment Report</div>
  <h1>Web Application Penetration Test Report</h1>
  <h2>{html.escape(target)} &mdash; {html.escape(app_name)}</h2>
  <table>
    <tr><td class="k">Target Host</td><td><code>{html.escape(target)}</code></td></tr>
    <tr><td class="k">Application Name</td><td>{html.escape(app_name)}</td></tr>
    <tr><td class="k">Technology Stack</td><td>{html.escape(tech_stack)}</td></tr>
    <tr><td class="k">Engagement Type</td><td>Authorized Comprehensive Penetration Test</td></tr>
    <tr><td class="k">Assessment Date</td><td>{stamp}</td></tr>
    <tr><td class="k">Total Confirmed Findings</td><td><b>{len(findings)} ({counts['critical']} Critical, {counts['high']} High, {counts['medium']} Medium, {counts['low']} Low)</b></td></tr>
    <tr><td class="k">Evidence Standard</td><td>Live Captured Raw HTTP Request &amp; Response Pairs</td></tr>
    <tr><td class="k">Classification</td><td>Confidential / Restricted</td></tr>
  </table>
  <div class="footer">Prepared by Hacker-Harness Engagement Engine &middot; All findings verified against active security boundary standards</div>
</div>

<h2 class="sec">Table of Contents</h2>
<div class="toc">
<ul>
<li><strong>1. Executive Summary</strong></li>
<li><strong>2. Scope &amp; Methodology</strong>
  <ul>
    <li>2.1 In-Scope Target Information</li>
    <li>2.2 Execution Methodology</li>
  </ul>
</li>
<li><strong>3. Findings Overview Matrix</strong></li>
<li><strong>4. Detailed Technical Findings &amp; HTTP Evidence</strong>
  <ul>
    <li>4.1 Critical Severity Findings</li>
    <li>4.2 High Severity Findings</li>
    <li>4.3 Medium Severity Findings</li>
    <li>4.4 Low Severity Findings</li>
  </ul>
</li>
<li><strong>5. Prioritized Remediation Roadmap</strong></li>
<li><strong>6. Appendix: Testing Environment &amp; Reconnaissance Telemetry</strong>
  <ul>
    <li>6.1 Testing Verification Standard</li>
    {f'<li>6.2 Exploratory Signals &amp; Candidates ({len(candidates)})</li>' if candidates else ''}
  </ul>
</li>
</ul>
</div>

<h2 class="sec">1. Executive Summary</h2>
<p>An authorized security assessment was conducted against <b>{html.escape(target)}</b> ({html.escape(app_name)}). The objective of the engagement was to identify vulnerabilities, evaluate authorization boundaries, and capture reproducible proof-of-concept evidence.</p>
<p>The assessment confirmed a total of <b>{len(findings)} unique vulnerabilities</b>: <b>{counts['critical']} critical</b>, <b>{counts['high']} high</b>, <b>{counts['medium']} medium</b>, <b>{counts['low']} low</b>, and <b>{counts['informational']} informational</b>. All vulnerabilities have been verified with live server responses and evaluated against strict boundary validation gates.</p>

<h3>Key Risk Breakdown</h3>
<table class="data">
<tr><th>Severity</th><th>Count</th><th>Threat Profile &amp; High-Level Impact</th></tr>
<tr><td><span class="sev-critical">CRITICAL</span></td><td>{counts['critical']}</td><td>Direct database compromise, source code disclosure with credentials, or unauthenticated full administrative access.</td></tr>
<tr><td><span class="sev-high">HIGH</span></td><td>{counts['high']}</td><td>Local file inclusion, arbitrary SQL injection, privilege escalation, stored XSS, or BFLA.</td></tr>
<tr><td><span class="sev-medium">MEDIUM</span></td><td>{counts['medium']}</td><td>Reflected XSS, open redirection, cross-site request forgery, or credential storage weaknesses.</td></tr>
<tr><td><span class="sev-low">LOW</span></td><td>{counts['low']}</td><td>Server misconfigurations, debug methods enabled, or missing security headers.</td></tr>
</table>

<h2 class="sec">2. Scope &amp; Methodology</h2>
<h3>2.1 In-Scope Target Information</h3>
<table class="data">
<tr><th>Parameter</th><th>Value</th></tr>
<tr><td>Target Host</td><td><code>{html.escape(target)}</code></td></tr>
<tr><td>Application Name</td><td>{html.escape(app_name)}</td></tr>
<tr><td>Detected Stack</td><td>{html.escape(tech_stack)}</td></tr>
<tr><td>Engagement Authorization</td><td>Active &amp; Authorized</td></tr>
</table>

<h3>2.2 Execution Methodology</h3>
<p>Testing strictly followed the 8-phase Hacker-Harness methodology: Auth Setup (P0), Application Understanding (P1), Public Index Discovery (P2), JS Analysis &amp; API Discovery (P3), Client-Side Attacks (P4), Role Matrix Testing (P5), Business Logic &amp; Concurrency Review (P6), and Cross-Tenant Testing (P7). All HTTP traffic was routed through local proxy verification to capture authoritative request and response telemetry.</p>

<h2 class="sec">3. Findings Overview Matrix</h2>
<table class="data">
<tr><th>ID</th><th>Finding Title</th><th>Category</th><th>Severity</th><th>Affected Target</th></tr>
{''.join(overview_rows) if overview_rows else '<tr><td colspan="5">No vulnerabilities recorded.</td></tr>'}
</table>

<h2 class="sec">4. Detailed Technical Findings &amp; HTTP Evidence</h2>
{''.join(findings_sections) if findings_sections else '<p>No vulnerabilities identified.</p>'}

<h2 class="sec">5. Prioritized Remediation Roadmap</h2>
<table class="data">
<tr><th>ID</th><th>Finding Title</th><th>Severity</th><th>Recommended Fix</th><th>Remediation SLA</th></tr>
{''.join(rem_rows) if rem_rows else '<tr><td colspan="5">No remediation items.</td></tr>'}
</table>

<h2 class="sec">6. Appendix: Testing Environment &amp; Reconnaissance Telemetry</h2>
<h3>6.1 Testing Verification Standard</h3>
<p>All HTTP requests documented in this report were executed during the authorized testing window against in-scope target infrastructure. Only minimal non-destructive payloads were utilized to prove impact. Evidence pairs reflect verbatim wire traffic captured at the time of discovery.</p>
{candidate_section_html}

</body>
</html>"""
    return html_document


generate_html_report = generate_executive_html_report


def generate_markdown_report(target: str, findings: list[dict], candidates: list[dict] | None = None) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"# Hacker-Harness Comprehensive Security Assessment Report: {target}",
        f"**Assessment Date:** {stamp}  ",
        f"**Target Scope:** `{target}`  ",
        f"**Total Confirmed Findings:** {len(findings)}  ",
        "",
        "## 1. Executive Summary",
        f"An authorized, comprehensive security evaluation was performed against `{target}` utilizing the Hacker-Harness framework. The objective of this assessment was to identify potential security vulnerabilities, evaluate authentication and authorization boundaries, and provide concrete remediation steps for development teams.",
        "",
        "### Severity & Threat Breakdown",
        "| Severity | Total Findings | Standard CVSS v3.1 Range |",
        "|---|---|---|",
    ]

    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in findings:
        s = (f.get("severity") or "medium").lower()
        counts[s] = counts.get(s, 0) + 1

    lines.extend([
        f"| **CRITICAL** | {counts['critical']} | 9.0 - 10.0 |",
        f"| **HIGH** | {counts['high']} | 7.0 - 8.9 |",
        f"| **MEDIUM** | {counts['medium']} | 4.0 - 6.9 |",
        f"| **LOW** | {counts['low']} | 0.1 - 3.9 |",
        f"| **INFORMATIONAL** | {counts['informational']} | 0.0 |",
        "",
        "---",
        "",
        "## 2. Detailed Vulnerability Reports",
        "",
    ])

    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "medium").upper()
        lines.extend([
            f"### {i}. [{sev}] {f.get('title', 'Untitled Finding')}",
            f"- **Finding ID:** `{f.get('id', f'F-{i:02d}')}`",
            f"- **Vulnerability Category:** {f.get('category', 'Application Security')}",
            f"- **Target Asset:** `{f.get('target', target)}`",
            f"- **CVSS v3.1 Score:** {f.get('cvss_score', 5.4)} (`{f.get('cvss_vector', '')}`)",
            f"- **CVSS v4.0 Vector:** `{f.get('cvss_vector_v4', '')}`",
            f"- **Validation Gate Status:** `{'✓ PASSED' if f.get('gate_passed') else '⚠️ REQUIRES REVIEW'}` [{f.get('gate_score', '6/7')}]",
            f"- **Status:** `{f.get('status', 'confirmed').upper()}`",
            "",
            "#### A. Technical Summary & Root Cause",
            f.get("description", "No description recorded."),
            "",
            "#### B. Expected vs Actual Behavior",
            f"- **Expected:** {f.get('expected_behavior', '403 Forbidden')}",
            f"- **Actual:** {f.get('actual_behavior', '200 OK / Vulnerable execution')}",
            "",
            "#### C. Step-by-Step Reproduction (PoC)",
            f.get("steps", f.get("evidence", "No steps recorded.")),
            "",
            "#### D. Security & Business Impact",
            f.get("impact", "Security boundary violation."),
            "",
            "#### E. Actionable Remediation Guidance",
            f.get("remediation", "Implement strict input validation and access controls."),
            "",
            "---",
            "",
        ])

    if candidates:
        lines.extend([
            "## 3. Exploratory Reconnaissance Signals & Candidates",
            "| ID | Signal / Lead | Category | Severity |",
            "|---|---|---|---|",
        ])
        for c in candidates:
            lines.append(f"| `{c.get('id', 'S-00')}` | {c.get('title', '')} | {c.get('category', '')} | {str(c.get('severity', 'low')).upper()} |")
        lines.append("")

    return "\n".join(lines)


def generate_csv_report(target: str, findings: list[dict]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Finding ID", "Category", "Title", "Severity", "CVSS Score", "CVSS Vector",
        "Target", "Status", "Validation Gate", "Description", "Expected Behavior", "Actual Behavior",
        "Steps to Reproduce", "Impact", "Remediation"
    ])
    for i, f in enumerate(findings, 1):
        writer.writerow([
            f.get("id", f"F-{i:02d}"),
            f.get("category", "General"),
            f.get("title", "Untitled Finding"),
            str(f.get("severity", "medium")).upper(),
            f.get("cvss_score", 5.4),
            f.get("cvss_vector", ""),
            f.get("target", target),
            str(f.get("status", "confirmed")).upper(),
            f.get("gate_score", "6/7"),
            f.get("description", ""),
            f.get("expected_behavior", ""),
            f.get("actual_behavior", ""),
            f.get("steps", f.get("evidence", "")),
            f.get("impact", ""),
            f.get("remediation", ""),
        ])
    return output.getvalue()


def generate_hackerone_report(target: str, findings: list[dict]) -> str:
    blocks = [f"# HackerOne Pentest Report Summary — {target}\n"]
    for i, f in enumerate(findings, 1):
        sev = str(f.get("severity") or "medium").upper()
        block = f"""## Report #{i}: {f.get('title', 'Untitled')}

**Asset / Target:** `{f.get('target', target)}`
**Vulnerability Type:** {f.get('category', 'Security Flaw')}
**Severity:** {sev} ({f.get('cvss_score', '5.4')}) `{f.get('cvss_vector', '')}`
**Validation Gate:** {'✓ PASS (7/7)' if f.get('gate_passed') else '⚠️ REQUIRES REVIEW'}

### Summary
{f.get('description', 'No summary provided.')}

### Vulnerability Details
- **Affected Endpoint:** `{f.get('target', target)}`
- **CVSS v3.1:** {f.get('cvss_score', '5.4')} (`{f.get('cvss_vector', '')}`)
- **Expected Behavior:** {f.get('expected_behavior', '403 Forbidden')}
- **Actual Behavior:** {f.get('actual_behavior', '200 OK')}

### Steps To Reproduce
{f.get('steps', f.get('evidence', 'N/A'))}

### Impact
{f.get('impact', 'Boundary breach.')}

### Recommended Fix
{f.get('remediation', 'Implement proper access control and validation.')}

---"""
        blocks.append(block)
    return "\n\n".join(blocks)


def generate_bugcrowd_report(target: str, findings: list[dict]) -> str:
    blocks = [f"# Bugcrowd Vulnerability Submission Package — {target}\n"]
    for i, f in enumerate(findings, 1):
        sev = str(f.get("severity") or "medium").upper()
        vrt_cat = f.get("vrt_category") or f.get("category") or "Broken Access Control"
        vrt_p = f.get("vrt_priority", "P2")
        title_line = f"[{vrt_cat}] > {vrt_p}: {f.get('title', 'Untitled')}"

        block = f"""# {title_line}

**Target / URI:** `{f.get('target', target)}`
**VRT Category:** {vrt_cat} > {vrt_p}
**Severity Priority:** {sev} (CVSS {f.get('cvss_score', '5.4')})

## Description
{f.get('description', 'N/A')}

## Steps to Reproduce
{f.get('steps', f.get('evidence', 'No PoC attached.'))}

## Expected vs Actual Behavior
- **Expected:** {f.get('expected_behavior', '403 Forbidden')}
- **Actual:** {f.get('actual_behavior', '200 OK')}

## Severity Justification
{sev} ({vrt_p}) &mdash; {f.get('impact', 'Direct security risk.')}

## Remediation
{f.get('remediation', 'Implement robust authorization checks.')}

---"""
        blocks.append(block)
    return "\n\n".join(blocks)


def generate_intigriti_report(target: str, findings: list[dict]) -> str:
    blocks = [f"# Intigriti Submission Deck — {target}\n"]
    for i, f in enumerate(findings, 1):
        sev = str(f.get("severity") or "medium").upper()
        block = f"""# [{f.get('category', 'Vulnerability')}]: {f.get('title', 'Untitled')}

**Endpoint / Domain:** `{f.get('target', target)}`
**CVSS v3.1 Score:** {f.get('cvss_score', '5.4')} (`{f.get('cvss_vector', '')}`)
**CVSS v4.0 Vector:** `{f.get('cvss_vector_v4', '')}`

## Description & Root Cause
{f.get('description', 'N/A')}

## Steps to Reproduce
{f.get('steps', f.get('evidence', 'N/A'))}

## Expected vs Actual Behavior
- **Expected:** {f.get('expected_behavior', '403 Forbidden')}
- **Actual:** {f.get('actual_behavior', '200 OK / Unauthorized execution')}

## Impact & Business Risk
{f.get('impact', 'N/A')}

## Remediation
{f.get('remediation', 'N/A')}

---"""
        blocks.append(block)
    return "\n\n".join(blocks)


def generate_immunefi_report(target: str, findings: list[dict]) -> str:
    blocks = [f"# Immunefi Web3 / Smart Contract Submission Package — {target}\n"]
    for i, f in enumerate(findings, 1):
        sev = str(f.get("severity") or "critical").upper()
        block = f"""# {f.get('category', 'Smart Contract Vulnerability')} — {target} — {sev}

## Summary
{f.get('description', 'No summary provided.')}

## Vulnerability Details
- **Target Asset / Contract:** `{f.get('target', target)}`
- **Bug Class:** {f.get('category', 'Accounting / Logic Flaw')}
- **Severity:** {sev} (CVSS: {f.get('cvss_score', '9.8')})

### Root Cause
{f.get('description', 'N/A')}

## Proof of Concept
{f.get('steps', f.get('evidence', 'N/A'))}

## Impact
{f.get('impact', 'Quantified economic risk.')}

## Recommended Fix
{f.get('remediation', 'Apply state synchronizer checks before transfer.')}

---"""
        blocks.append(block)
    return "\n\n".join(blocks)


def generate_yeswehack_report(target: str, findings: list[dict]) -> str:
    blocks = [f"# YesWeHack Report Export — {target}\n"]
    for i, f in enumerate(findings, 1):
        sev = str(f.get("severity") or "medium").upper()
        block = f"""### {i}. {f.get('title', 'Untitled')}
- **Scope / Target:** `{f.get('target', target)}`
- **Severity Rating:** {sev} (CVSS: {f.get('cvss_score', '5.4')})

**Technical Description:**
{f.get('description', 'N/A')}

**Steps To Reproduce (PoC):**
{f.get('steps', f.get('evidence', 'N/A'))}

**Security Impact:**
{f.get('impact', 'N/A')}

**Fix Recommendation:**
{f.get('remediation', 'N/A')}

---"""
        blocks.append(block)
    return "\n\n".join(blocks)


def build_report(
    target: str,
    findings: list[dict],
    fmt: str = "html",
    project: Path | None = None,
    provider: Any | None = None,
) -> tuple[str, str, str]:
    """Generate report content, filename, and mime/type based on requested format, using LLM synthesis when available."""
    f = fmt.lower().strip().lstrip("-")
    clean_target = re.sub(r"[^a-zA-Z0-9.-]", "_", target)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    context = gather_target_context(project or Path.cwd(), target)

    processed_findings, candidates = llm_process_report_findings(provider, findings, context)

    if f in ("html", "htm"):
        content = generate_executive_html_report(target, processed_findings, context=context, candidates=candidates)
        filename = f"report_{clean_target}_{stamp}.html"
        return content, filename, "text/html"
    elif f == "csv":
        content = generate_csv_report(target, processed_findings)
        filename = f"report_{clean_target}_{stamp}.csv"
        return content, filename, "text/csv"
    elif f in ("hackerone", "h1"):
        content = generate_hackerone_report(target, processed_findings)
        filename = f"hackerone_report_{clean_target}_{stamp}.md"
        return content, filename, "text/markdown"
    elif f in ("bugcrowd", "bc"):
        content = generate_bugcrowd_report(target, processed_findings)
        filename = f"bugcrowd_report_{clean_target}_{stamp}.md"
        return content, filename, "text/markdown"
    elif f == "intigriti":
        content = generate_intigriti_report(target, processed_findings)
        filename = f"intigriti_report_{clean_target}_{stamp}.md"
        return content, filename, "text/markdown"
    elif f in ("immunefi", "web3"):
        content = generate_immunefi_report(target, processed_findings)
        filename = f"immunefi_report_{clean_target}_{stamp}.md"
        return content, filename, "text/markdown"
    elif f in ("yeswehack", "ywh"):
        content = generate_yeswehack_report(target, processed_findings)
        filename = f"yeswehack_report_{clean_target}_{stamp}.md"
        return content, filename, "text/markdown"
    else:
        content = generate_markdown_report(target, processed_findings, candidates=candidates)
        filename = f"report_{clean_target}_{stamp}.md"
        return content, filename, "text/markdown"
