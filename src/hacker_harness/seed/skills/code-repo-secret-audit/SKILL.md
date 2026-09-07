---
name: code-repo-secret-audit
description: GitHub, GitLab, and source code repository recon, dorking, commit history secret auditing, and PR/issue leaks.
playbook: web-security
---

# Code Repository & Secret Reconnaissance Audit

## Attack Vector Summary
Source code repository recon involves scanning public organizations, contributor profiles, git histories, commits, issues, and pull requests to discover leaked API keys, tokens, hardcoded credentials, and infrastructure blueprints.

## Tactical Heuristics & Step-by-Step Flow

### 1. Manual & Automated GitHub Dork Matrix
Run exhaustive queries across target organizations (`org:TARGET_ORG` or domain keywords).

```text
=== Files ===
filename:manifest.xml
filename:travis.yml
filename:vim_settings.xml
filename:database
filename:prod.exs NOT prod.secret.exs
filename:prod.secret.exs
filename:.npmrc _auth
filename:.dockercfg auth
filename:WebServers.xml
filename:.bash_history <DOMAIN>
filename:sftp-config.json
filename:sftp.json path:.vscode
filename:secrets.yml password
filename:.esmtprc password
filename:passwd path:etc
filename:dbeaver-data-sources.xml
path:sites databases password
filename:config.php dbpasswd
filename:configuration.php JConfig password
filename:.sh_history
shodan_api_key language:python
filename:shadow path:etc
JEKYLL_GITHUB_TOKEN
filename:proftpdpasswd
filename:.pgpass
filename:idea14.key
filename:hub oauth_token
HEROKU_API_KEY language:json
HEROKU_API_KEY language:shell
SF_USERNAME salesforce
filename:.bash_profile aws
extension:json api.forecast.io
filename:.env MAIL_HOST=smtp.gmail.com
filename:wp-config.php
extension:sql mysql dump
filename:credentials aws_access_key_id
filename:id_rsa
filename:id_dsa

=== Languages ===
language:python <DOMAIN>
language:php <DOMAIN>
language:sql <DOMAIN>
language:html password
language:perl password
language:shell <DOMAIN>
language:java api
HOMEBREW_GITHUB_API_TOKEN language:shell

=== API Keys, Tokens, Passwords ===
api_key
"api keys"
authorization_bearer:
oauth
auth
authentication
client_secret
api_token:
"api token"
client_id
password
user_password
user_pass
passcode
client_secret
secret
password hash
OTP
user auth

=== Extensions ===
extension:pem private
extension:ppk private
extension:sql mysql dump
extension:sql mysql dump password
extension:json api.forecast.io
extension:json mongolab.com
extension:yaml mongolab.com
extension:ica [WFClient] Password=
extension:avastlic "support.avast.com"
extension:json googleusercontent client_secret
```

### 2. Automated Dorking & Tool Orchestration

```bash
# 1. Automated GitHub Search API Sweeps (with GH_TOKEN)
while IFS= read -r keyword; do
  [ -z "$keyword" ] && continue
  count=$(curl -s -H "Authorization: token $GH_TOKEN" \
    "https://api.github.com/search/code?q=${keyword}+org:TARGET_ORG&per_page=1" 2>/dev/null | \
    python3 -c "import json,sys; print(json.load(sys.stdin).get('total_count',0))" 2>/dev/null)
  [ "$count" -gt 0 ] && echo "🔴 $keyword → $count results" >> Recon/target_gh_dorks.txt
done < /home/kali/Tools/github_dorks.txt

# 2. TruffleHog (Deep Git History & Verified Live Secret Scanning)
trufflehog github --org=TARGET_ORG --only-verified
trufflehog git file:///path/to/repo --json | tee Recon/target_trufflehog.txt

# 3. Gitleaks (Fast Regex Pattern Auditing)
gitleaks detect --source /path/to/repo --report-format json --report-path Recon/gitleaks_report.json

# 4. Whispers / Detect-Secrets (Static credential extraction from config formats)
whispers /path/to/repo/ > Recon/whispers_secrets.json
detect-secrets scan /path/to/repo > Recon/detect_secrets.json

# 5. Git-Hound / Git-Dorks (Sensitive regex search in commit history)
git log -p -S "api_key" --all | tee Recon/target_gh_commit_leaks.txt
```

### 3. PR & Issue Discussion Leak Inspection
Developers often push credentials temporarily for debugging and delete them in follow-up commits. Inspect PR discussion comments, issue bodies, and pull request commit histories:
- Search PR bodies for: `internal`, `staging`, `token`, `bearer`, `aws`, `password`, `login`.
- Save PR leaks to `Recon/target_gh_pr_leaks.txt`.

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| Leaked Cloud IAM Keys | Developer commits AWS/GCP key in test file | `AKIA[0-9A-Z]{16}` in repository commit | Active STS caller identity via `aws sts get-caller-identity` |
| Internal Staging URL in PR | PR description references staging endpoints | `https://staging-internal.target.com` | Live unauthenticated staging service |
| Hardcoded JWT / Session Secret | App signing secret committed in repository | `JWT_SECRET = "supersecret123"` | Ability to forge arbitrary admin JWT tokens |

## Evidence Collection & Validation Gate
- Must capture commit hash, file path, line numbers, and active verification of discovered secrets.
- Redact sensitive token bytes when saving to reports.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
