---
name: ad-kerberos-delegation-abuse
description: Active Directory Kerberos delegation assessment, unconstrained and constrained delegation analysis, Resource-Based Constrained Delegation (RBCD), and AS-REP roasting enumeration.
---

# Active Directory Kerberos Delegation & Service Ticket Auditing

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Verified Active Directory domain, Domain Controller FQDN, and organizational units in `scope.yaml`.
- **Target Credentials:** Low-privilege domain user credentials (`DOMAIN\username:password`) or Kerberos TGT.
- **Traffic Routing:** Route LDAP, Kerberos (port 88), and RPC traffic through authorized testing interfaces.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: AS-REP Roasting (Pre-Authentication Disabled)
Enumerate user accounts configured with `DONT_REQ_PREAUTH` (Kerberos pre-authentication disabled):
```bash
# LDAP search for preauth-disabled accounts
ldapsearch -H ldap://<DC-IP> -x -D "username@domain.local" -w "password" \
  -b "DC=domain,DC=local" "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```

### Step 2: Kerberoasting Service Principal Names (SPNs)
Enumerate user accounts with configured `servicePrincipalName` attributes and request TGS tickets:
```bash
# Query accounts with SPNs
ldapsearch -H ldap://<DC-IP> -x -D "username@domain.local" -w "password" \
  -b "DC=domain,DC=local" "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName
```

### Step 3: Kerberos Delegation Misconfiguration Auditing
Audit accounts with dangerous delegation flags:
1. **Unconstrained Delegation (`TRUSTED_FOR_DELEGATION` / flag 524288):**
   * If a Domain Controller or High-Value Admin connects to this service, their full TGT is cached in LSASS.
   * Query: `(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))`
2. **Constrained Delegation with Protocol Transition (S4U2Self / S4U2Proxy):**
   * Check `msDS-AllowedToDelegateTo` and `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` (flag 16777216).
   * Allows the service to impersonate arbitrary domain users (including Domain Admins) to configured target services.
3. **Resource-Based Constrained Delegation (RBCD):**
   * If caller has write permissions (`GenericWrite`, `GenericAll`, `WriteDacl`) over a target computer object, set `msDS-AllowedToActOnBehalfOfOtherIdentity`.

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Vulnerability Vector | Mechanism | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **RBCD via Machine Account Creation** | Domain `MachineAccountQuota > 0` + write DACL | Create machine account $\rightarrow$ write to target `msDS-AllowedToActOnBehalfOfOtherIdentity` | S4U2Proxy TGS impersonating Admin |
| **Service Account Kerberoasting** | Weak password on SPN-bearing user account | Request RC4/AES TGS ticket for offline cracking | `$krb5tgs$23$...` hash matching dictionary |
| **Unconstrained Delegation on Web Server** | Compromised IIS machine account has unconstrained delegation | Trigger PrintNightmare / SpoolSample RPC to force DC auth | DC machine account TGT captured |
| **LAPS Password Exposure** | `ms-Mcs-AdmPwd` attribute readable by low-priv users | Low-privilege LDAP query reads plaintext LAPS passwords | Cleartext local Administrator password returned |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture LDAP query outputs, Kerberos ticket metadata, or delegation attribute values (`msDS-AllowedToDelegateTo`).
2. **Impact Proof:** Demonstrate the theoretical impersonation graph without modifying domain credentials or causing service disruption.
3. **Remediation:** Remove unconstrained delegation, configure sensitive admin accounts as "Account is sensitive and cannot be delegated", set `MachineAccountQuota` to 0, and use Group Managed Service Accounts (gMSA) with strong passwords.
