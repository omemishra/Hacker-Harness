---
name: perimeter-exchange-ntlm-info
description: Microsoft Exchange, OWA, EWS, ActiveSync, and IIS NTLM Type-2 challenge header decoding to extract internal AD domain, server names, and OS build info without authentication.
playbook: web-security
---

# Perimeter Exchange & IIS NTLM Information Disclosure

## Attack Vector Summary
Microsoft IIS, Exchange Server (OWA, EWS, ActiveSync, Autodiscover, RPC/MAPI), and ASP.NET applications configured with Windows Integrated Authentication (NTLM) respond to anonymous NTLM Negotiate (Type-1) requests with an NTLM Challenge (Type-2) containing unauthenticated internal Active Directory metadata (Internal Domain Name, Forest Name, NetBIOS Name, Internal Hostname, and OS version).

## Tactical Heuristics & Step-by-Step Flow

### 1. High-Probability Endpoints
Probe common Exchange and IIS NTLM authentication endpoints:
- `/owa/auth/owaauth.dll`
- `/ews/exchange.asmx`
- `/Microsoft-Server-ActiveSync`
- `/autodiscover/autodiscover.xml`
- `/rpc/rpcproxy.dll`
- `/ecp/`
- `/aspnet_client/`

### 2. NTLM Type-1 Probe & Base64 Decoding
Send an anonymous NTLM Type-1 header:

```http
GET /ews/exchange.asmx HTTP/1.1
Host: mail.target.com
Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==
```

Receive `401 Unauthorized` with `WWW-Authenticate: NTLM <Type-2 Base64>`:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: NTLM TlRMTVNTUAACAAAADAAMADgAAAAFgooC...
```

### 3. Automated Parsing with nmap / python
```bash
# Using nmap http-ntlm-info script
nmap -p 443 --script http-ntlm-info --script-args http-ntlm-info.root=/ews/exchange.asmx mail.target.com

# Python extraction
python3 -c "
import base64, sys
# Decodes Target Name, NetBIOS computer name, NetBIOS domain, DNS domain, DNS computer name, Forest name
"
```

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| Exchange Internal Topology Leak | Unauthenticated Type-2 NTLM challenge response | NTLMSSP challenge returned on `/ews` | Leaked internal FQDN (e.g. `EXCH01.corp.internal.target.com`) |
| Domain Hierarchy Enumeration | Autodiscover endpoint reveals AD Forest name | `Target Name: CORP-AD` in decoded NTLM | Unauthenticated Active Directory forest naming enumeration |
| Target Machine OS Fingerprint | NTLM structure bytes include major/minor Windows build | `OS Version: 10.0.17763 (Windows Server 2019)` | Exact unauthenticated OS kernel build identification |

## Evidence Collection & Validation Gate
- Must capture raw HTTP `Authorization: NTLM` request and server `WWW-Authenticate: NTLM` response.
- Provide clean decoded dump of Domain Name, Computer Name, DNS Tree Name, and OS Build.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
