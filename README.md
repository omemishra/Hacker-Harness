# 🛡️ Hacker-Harness

> **Authorization-Aware Agentic Penetration Testing & Attack Orchestration Harness**

**Hacker-Harness (`hh`)** is a modular, operator-controlled offensive security framework that combines Large Language Model reasoning with deterministic penetration testing execution. Built on a 3-tier architecture (Atomic Skills, Stage Manifests, and DAG Workflows), it enforces strict tool-layer authorization, eliminates context drift, supports Caido proxy interception, and provides automated, multi-platform vulnerability reporting.

---

## 📑 Table of Contents

1. [Key Features](#-key-features)
2. [Architecture Overview](#-architecture-overview)
3. [Prerequisites & Installation](#-prerequisites--installation)
4. [Quickstart: Step-by-Step Pentest Guide](#-quickstart-step-by-step-pentest-guide)
   - [Step 1: Initialize Workspace](#step-1-initialize-workspace)
   - [Step 2: Configure Authorization Scope (Scope Gate)](#step-2-configure-authorization-scope-scope-gate)
   - [Step 3: Configure Settings & Providers](#step-3-configure-settings--providers)
   - [Step 4: Launch the Interactive Deck](#step-4-launch-the-interactive-deck)
   - [Step 5: Run Methodologies or Workflows](#step-5-run-methodologies-or-workflows)
   - [Step 6: Validate, Retest, and Generate Reports](#step-6-validate-retest-and-generate-reports)
5. [Scope Gate & Safety Guardrails](#-scope-gate--safety-guardrails)
6. [Interactive Terminal UI & Commands](#-interactive-terminal-ui--commands)
7. [Tactical Skills & Dynamic Attack Pivoting (`/pivot`)](#-tactical-skills--dynamic-attack-pivoting-pivot)
8. [Caido MCP & Proxy Interception](#-caido-mcp--proxy-interception)
9. [7-Question Validation Gate & Retesting (`/validate`, `/retest`)](#-7-question-validation-gate--retesting-validate-retest)
10. [Multi-Platform Report Generation (`/report`)](#-multi-platform-report-generation-report)
11. [Authoring Skills, Workflows & Methodologies](#-authoring-skills-workflows--methodologies)
12. [Development & Testing](#-development--testing)
13. [Security Model & Disclaimer](#-security-model--disclaimer)

---

## ⚡ Key Features

- 🎯 **Strict Tool-Layer Scope Enforcement:** Technical guardrails block out-of-scope network calls, domain targets, and subnets at execution time. Exclusions override inclusions.
- 🧩 **Modular 3-Tier Lego Architecture:** Combine atomic offensive skills (`SKILL.md`), file-gated stage manifests (`.json`), and executable DAG pipelines (`.yaml`).
- 🔄 **Dynamic Skill Pivoting (`/pivot`):** Heuristic and attack-graph-driven recommendation engine to pivot from low-severity findings into high-impact multi-stage exploits.
- 📡 **Full Caido MCP Integration:** Native routing for replay, automation, sitemap indexing, and request/response tampering.
- 🛡️ **7-Question Validation Gate (`/validate`):** Pre-flight verification standard ensuring zero-sampling coverage and eliminating false positives before reporting.
- 🔁 **Differential Retesting Engine (`/retest`):** Granular, automated re-verification of individual finding IDs or entire vulnerability catalogs.
- 📋 **Multi-Platform Report Generator (`/report`):** AI-synthesized executive reports and native exports for **HTML, CSV, HackerOne, Bugcrowd, Intigriti, Immunefi, and YesWeHack**.
- 🖥️ **Interactive Terminal Deck:** Full-screen responsive TUI featuring slash-command autosuggestion, inline tool cards, real-time context meters, and live attack tree visualizers (`/tree`).

---

## 🏗️ Architecture Overview

Hacker-Harness cleanly separates tactical attack knowledge from orchestration and gating:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                        Operator & Interactive CLI                       │
│        (/use <methodology>  |  /workflow <dag>  |  /pivot  |  /report)  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
           ┌─────────────────────────┼─────────────────────────┐
           ▼                         ▼                         ▼
┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│    Atomic Skills     │  │   Stage Manifests    │  │     YAML DAGs        │
│  (.hacker-harness/   │  │  (.hacker-harness/   │  │   (workflows/        │
│      skills/)        │  │      stages/)        │  │     *.yaml)          │
│                      │  │                      │  │                      │
│ Concrete payloads,   │  │ File-gated contracts │  │ Automated pipelines  │
│ heuristics, pivots   │  │ (requires / writes)  │  │ with approval gates  │
└──────────────────────┘  └──────────────────────┘  └──────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                  Authorization & Scope Enforcement Layer                │
│  - scope.yaml matching (wildcard, IP, CIDR, exclusions)                │
│  - Host-scoped HTTP approvals & safe passive recon allowances           │
│  - SQLite audit ledger & engagement root isolation                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Prerequisites & Installation

### Prerequisites

- **Python 3.11+**
- **Git**
- Optional Offensive Tools (for local workflows): `caido`, `nmap`, `masscan`, `ffuf`, `httpx`, `subfinder`, `nuclei`, `playwright`, `bandit`, `semgrep`.

### Installation

#### 1. Clone and Install (Editable / Development Mode)
```bash
git clone https://github.com/omemishra/Hacker-Harness.git
cd Hacker-Harness
pip install -e . --break-system-packages
```

Or run the automated installer:
```bash
./scripts/install.sh
```

#### 2. Install with `uv` (Isolated Tool)
```bash
uv tool install .
```

#### 3. Path Setup & Verification
Ensure your local bin directory is on your `PATH`:
```bash
export PATH="$HOME/.local/bin:$PATH"
hh --version
```

Verify your environment configuration:
```bash
hh doctor
```

---

## 🚀 Quickstart: Step-by-Step Pentest Guide

### Step 1: Initialize Workspace

Create a dedicated workspace for your pentest engagement:

```bash
mkdir -p ~/pentest-workspace && cd ~/pentest-workspace
hh init
```

This creates the project layout:
```text
.hacker-harness/
├── scope.yaml          # Target boundaries & authorization rules
├── settings.json        # Provider keys, paths, and permissions
├── mcp.json             # Model Context Protocol servers (Caido, Playwright)
├── skills/              # Local atomic offensive skills
└── stages/              # Stage input/output contracts
```

---

### Step 2: Configure Authorization Scope (Scope Gate)

Edit `.hacker-harness/scope.yaml` to specify authorized targets and explicit exclusions:

```yaml
engagement: Acme Corp Web & API Pentest
authorized: true
owner: Security Team / Operator Name
expires_at: 2026-12-31T23:59:59Z

targets:
  - value: "example.com"
  - value: "*.example.com"
  - value: "192.0.2.0/24"
  - value: ["api.example.com", "staging.example.com"]

excluded:
  - value: "payments.example.com"
  - value: "production-db.example.com"

rules:
  - "Maximum 10 requests per second rate limit"
  - "No destructive testing on production databases"
  - "Stop and notify immediately on 2FA/OTP or administrative lockout"
```

Verify that your scope is active and test individual endpoints against the scope engine:
```bash
hh scope show
hh scope check api.example.com          # Returns: ALLOWED (in-scope)
hh scope check payments.example.com     # Returns: BLOCKED (excluded)
hh scope check malicious.com            # Returns: BLOCKED (out-of-scope)
```

---

### Step 3: Configure Settings & Providers

Set your LLM provider API key in your environment:

```bash
# For DeepSeek (Recommended default):
export DEEPSEEK_API_KEY="sk-..."

# For Anthropic Claude:
export ANTHROPIC_API_KEY="sk-ant-..."

# For OpenAI:
export OPENAI_API_KEY="sk-..."
```

Optionally configure provider profiles and paths in `.hacker-harness/settings.json`:
```json
{
  "activeProvider": "deepseek-anthropic",
  "engagementRoot": "/home/kali/Targets",
  "knowledgePaths": [
    "/home/kali/Targets/methodology",
    "/home/kali/Targets/skills"
  ],
  "passiveDomains": [
    "*.shodan.io",
    "*.virustotal.com",
    "*.oast.me",
    "*.interact.sh"
  ],
  "permissions": {
    "commandMode": "engagement"
  },
  "ui": {
    "fullscreen": true,
    "largeBanner": true,
    "toolCardMode": "summary"
  }
}
```

---

### Step 4: Launch the Interactive Deck

Launch the full-screen interactive TUI:
```bash
hh chat
# or simply:
hh
```

The startup banner displays active models, active scope status, tool/skill counters, and quick hints:
```text
╭─── hh v1.7.27 ───────────────────────────────────────────────────────────────────╮
│                            │ Tips                                                │
│       Welcome back!        │ # for scope & targets                               │
│                            │ / for commands                                      │
│        █  █ ── █  █        │ ! to run shell commands                             │
│        █▀▀█ ── █▀▀█        │ ─────────────────────────────────────────────────── │
│        █  █ ── █  █        │ Scope & Tools                                       │
│                            │ SCOPE ACTIVE · 28 tools · 44 skills                 │
│     HACKER // HARNESS      │ ─────────────────────────────────────────────────── │
│                            │ Recent sessions                                     │
│     deepseek-v4-flash      │ • target-recon                                      │
│     deepseek-anthropic     │ • api-test                                          │
│                            │                                                     │
╰────────────────────────────┴─────────────────────────────────────────────────────╯
 Tip: `/copy code` grabs the last code block — `/copy cmd` grabs the last command
```

---

### Step 5: Run Methodologies or Workflows

#### Option A: Interactive Methodology (Chat Mode)
Load an interactive penetration testing methodology into context:
```text
/use genpentest
# or:
/use recon-workflow
```
- Step through stages sequentially with `/advance`.
- Artifacts (`ps_tokens.txt`, `APIendpoint.md`, `Vulnerabilities.md`) are written to the target directory.

#### Option B: Automated DAG Workflow (Pipeline Mode)
Execute a deterministic, automated workflow with human-in-the-loop approval gates:
```text
/workflow genpentest-deep.yaml target=example.com
# or:
/workflow recon-deep.yaml target=example.com
# or:
/workflow code-review.yaml target=https://github.com/org/repo
```

---

### Step 6: Validate, Retest, and Generate Reports

#### 1. Validate Findings with the 7-Question Gate:
```text
/validate F1
```

#### 2. Suggest Tactical Attack Pivots:
```text
/pivot F1
```

#### 3. Differential Regression Retesting:
```text
/retest example.com all
# or retest a specific finding:
/retest example.com F1
```

#### 4. Generate Multi-Platform Executive Reports:
```text
/report example.com --html
/report example.com --hackerone
/report example.com --bugcrowd
/report example.com --csv
```

---

## 🔒 Scope Gate & Safety Guardrails

Hacker-Harness enforces authorization at the tool boundary, not just in system prompts:

1. **Deterministic Target Filtering:** Every outbound IP, CIDR, and domain is verified against `scope.yaml`.
2. **Wildcard & Subdomain Rules:** `example.com` only matches the apex domain; `"*.example.com"` is required for subdomain authorization.
3. **Passive Recon Exemption (`passiveDomains`):** OSINT infrastructure (Censys, Shodan, Wayback CDX, CT logs) and out-of-band collaborator domains (Interactsh) are allowed for recon without compromising target safety.
4. **Command Modes:**
   - `"strict"` (Default): Prompts for operator approval on every shell execution and HTTP request.
   - `"engagement"`: Automatically executes in-scope commands and HTTP requests without repetitive prompts, while blocking out-of-scope targets and destructive actions.
   - `"standard"`: Skips approval prompts for fully autonomous local operations.
5. **Hard Safety Stops:**
   - **2FA/OTP Gate Halt:** The harness immediately stops and yields control to the operator upon detecting MFA or SMS/Email verification gates.
   - **Zero-Sampling Coverage:** Prevents skipping endpoints during access control matrices.

---

## 🖥️ Interactive Terminal UI & Commands

### Slash Commands Reference

| Command | Description | Example |
| :--- | :--- | :--- |
| `/help` | Display command help and usage instructions | `/help` |
| `/scope` | Display current scope status, target list, and expiry | `/scope` |
| `/skills` | List all discovered and loaded tactical offensive skills | `/skills` |
| `/methodologies` | Browse imported markdown methodologies | `/methodologies` |
| `/use <name>` | Load a methodology into interactive chat context | `/use genpentest` |
| `/advance` | Verify required stage deliverables and advance stage | `/advance` |
| `/workflows` | List all available executable YAML DAG workflows | `/workflows` |
| `/workflow <name>` | Execute a structured YAML DAG workflow | `/workflow recon-deep.yaml target=target.com` |
| `/pivot [finding]` | Calculate next-stage attack pivots for a finding | `/pivot F2` |
| `/validate [id]` | Execute the 7-Question pre-flight validation gate | `/validate F1` |
| `/retest [target]` | Differential retesting for candidate findings | `/retest target.com all` |
| `/report [target]` | Generate multi-platform vulnerability reports | `/report target.com --html` |
| `/tree [on\|off]` | Toggle real-time attack graph visualizer | `/tree on` |
| `/findings` | Display structured findings and evidence table | `/findings` |
| `/vulns` | Display contents of `Vulnerabilities.md` | `/vulns` |
| `/model [profile]` | Switch model profile or view active provider | `/model deepseek-anthropic` |
| `/context` | Display context-window usage and token metrics | `/context` |
| `/compact` | Compact conversational history to reclaim tokens | `/compact` |
| `/sessions` | List saved and resumable hunting sessions | `/sessions` |
| `/resume [id]` | Resume a previous hunting session by ID | `/resume 20260831_120000` |
| `/new` | Clear session state and start a clean hunt | `/new` |
| `/tools` | List all registered offensive tools & MCPs | `/tools` |
| `/mcp` | Inspect and manage Model Context Protocol servers | `/mcp` |
| `/tasks` | View ready task queue and dependency tree | `/tasks` |
| `/clear` | Clear current chat screen buffer | `/clear` |
| `/quit` | Exit Hacker-Harness | `/quit` |

### Keybindings & Shortcuts
- `Tab`: Auto-complete slash commands, subcommands, target hosts, workflows, and model profiles.
- `Right Arrow` or `Ctrl+F`: Accept ghost-text autosuggestion.
- `Escape + F`: Accept next word of autosuggestion.
- `Up / Down Arrow`: Cycle through persistent command history.
- `Ctrl+C`: Cancel current operation / interrupt model execution.

---

## 🎯 Tactical Skills & Dynamic Attack Pivoting (`/pivot`)

Hacker-Harness ships with over **40+ atomic offensive skills** stored in `.hacker-harness/skills/`:

- **Web Exploitation:** Polyglot XSS, IDOR / BOLA authorization, SSRF cloud metadata pivoting, Prototype Pollution, SQLi, Open Redirect, GraphQL abuse, CSP bypass gadgets.
- **Identity & Access:** OAuth 2.0 / OIDC redirection abuse, JWT tampering & key confusion, SAML assertion injection, MFA race conditions.
- **Active Directory & Infrastructure:** Kerberos unconstrained delegation, ADCS ESC1-ESC8 abuse, BloodHound graph pathfinding, Container breakout & cgroup escape.
- **Cloud Security:** AWS IAM privilege escalation, Azure Entra ID credential spray, GCP service account hijacking.
- **Source Code Audit:** Deep SAST & secret discovery (Semgrep, Bandit, Medusa, Trivy).

### Dynamic Skill Pivoting
Skills define a `pivots_to` attack graph in their metadata. When a vulnerability is recorded, the harness evaluates the evidence and suggests high-impact follow-up techniques:

```text
/pivot F1

┌── Attack Pivot Recommendations for [F1: SSRF in /api/export] ──────────┐
│  1. cloud-aws-iam-privesc        (Leverage IMDS credentials from SSRF) │
│  2. infra-container-escape-audit (Probe Docker socket / kubelet API)   │
│  3. ad-kerberos-delegation-abuse (Relay internal NTLM credentials)    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📡 Caido MCP & Proxy Interception

Hacker-Harness natively integrates with **Caido** via the Model Context Protocol (MCP):

1. **Traffic Capture:** Directs all security requests through Caido for tamper-proof logging.
2. **Capability Suite:**
   - `caido_send_request`: Send and inspect raw HTTP/HTTPS traffic.
   - `caido_replay`: Send requests to Caido Replay tab for manual review.
   - `caido_automate`: Run high-speed parameter fuzzing and payload mutations.
   - `caido_sitemap`: Query discovered endpoints and parameter hierarchies.
   - `caido_tamper`: Define proxy match-and-replace rules.

---

## 🛡️ 7-Question Validation Gate & Retesting (`/validate`, `/retest`)

### 7-Question Validation Gate
Before a candidate vulnerability is promoted to a confirmed finding, `/validate <id>` runs it through strict pre-flight validation:
1. Is the target host verified in-scope?
2. Is the vulnerability definitively confirmed with reproducible steps (not a theoretical inference)?
3. Has full parameter coverage been achieved (Zero-Sampling)?
4. Is the impact substantiated with raw HTTP request/response evidence?
5. Have false positives (e.g. static error pages, generic 200 OKs) been eliminated?
6. Are remediation recommendations specific to the target technology stack?
7. Is the report title formulated according to `[Bug Class] in [Endpoint] allows [Attacker Role] to [Impact]`?

### Differential Retesting Engine (`/retest`)
Re-evaluate confirmed findings against updated application versions to verify fixes or identify regressions:
```text
/retest example.com all
/retest example.com F2
```

---

## 📊 Multi-Platform Report Generation (`/report`)

Hacker-Harness compiles raw findings and engagement artifacts into executive-ready reports using an LLM synthesis and deduplication pipeline:

```bash
# Generate high-impact corporate HTML report with printable A4 styling
hh chat
> /report example.com --html

# Generate bug bounty platform formats:
> /report example.com --hackerone
> /report example.com --bugcrowd
> /report example.com --intigriti
> /report example.com --immunefi
> /report example.com --yeswehack

# Export to CSV or Markdown:
> /report example.com --csv
> /report example.com --markdown
```

### Report Features
- **Executive Summary:** Risk score metrics, critical findings breakdown, and threat analysis.
- **Zero-Theoretical Language:** Every finding includes exact, reproducible PoC steps and raw HTTP request/response payloads.
- **Candidate Signal Separation:** Confirmed high-severity vulnerabilities are clearly separated from exploratory reconnaissance signals and general security headers.

---

## 🛠️ Authoring Skills, Workflows & Methodologies

Hacker-Harness provides built-in authoring and validation CLI tools:

### Create and Validate a Skill
```bash
hh skill init my-new-skill
hh skill validate .hacker-harness/skills/my-new-skill/SKILL.md
```

### Create and Validate a Workflow
```bash
hh workflow init my-custom-dag
hh workflow validate workflows/my-custom-dag.yaml
```

### Create and Validate a Methodology
```bash
hh methodology init my-framework methodology/my-framework
hh methodology validate methodology/my-framework
```

---

## 🧪 Development & Testing

Run the test suite across all subsystems:

```bash
python3 -m unittest discover -s tests -t . -v
```

To run specific test modules:
```bash
python3 -m unittest tests/test_cli.py
python3 -m unittest tests/test_fullscreen.py
python3 -m unittest tests/test_tools.py
```

---

## ⚖️ Security Model & Disclaimer

- **Technical Guardrails:** Scope validation, destructive command blocking, and file confinement are enforced at the tool layer.
- **No Telemetry:** Hacker-Harness collects zero telemetry, usage analytics, or remote logs.
- **Operator Responsibility:** This harness is designed strictly for authorized penetration testing, bug bounty programs, and secure code review. Unauthorized access to computer systems is illegal. Always obtain written authorization prior to testing.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for details.
