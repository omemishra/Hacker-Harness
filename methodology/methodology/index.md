# Methodology Index

> Reusable hunting patterns for authorized engagements. Read before starting any new target.
> **RAG-FIRST:** For XSS, CSP, CORS, WAF bypass, cache poisoning, SSRF, or XS-Leaks — query `https://api.preview.is/search` first when available. Ground payloads in real writeups. Never guess.
> Updated: 2026-09-07

## Quick Reference

[[methodology/recon-quickref|Recon Framework — Quick Reference Card]]
> Single-page cheat sheet: all 20 R steps, 2 E steps, data flow, scope rules. Glance at this instead of opening the full framework.

## Recon Framework

[[methodology/recon-framework|Recon Framework — Phase 1 Workflow]]
> 20-step pipeline (R1-R20 + E1+E2): sensitive file exposure, katana, gau/wayback, responsive analysis, JS analysis, parameter discovery (gwjs→Arjun→GWJSAJQ), tech fingerprint, CSP bypass, open redirect, XSS/SQLi/SSTI, CSPP, SSRF, GitHub recon (dorking + secret scan + PR/commit/issue scan), code review (Bandit + Semgrep + Medusa + supply chain + HH deep review), port scan, directory fuzzing, 403 bypass, CORS check, SSL/certs, SQLi exploitation, LFI.
> **R1-R13** = core (always run). **R14-R20** = context-dependent (GitHub access, source code, infrastructure).

[[methodology/recon-workflow|Recon Workflow Rules]]
> Scope types (SCOPEONLY vs WILDCARD), R-step flow by bug type, plan.md requirements, prior knowledge injection, progress.md tracking, data flow chain (gwjs_endpoints → Arjun → mined_pendpoint → GWJSAJQ_urls), **dependency chains per bug type (XSS, SQLi, SSRF, etc.)**.

## Plan Template

[[methodology/recon-plan-template|Recon Plan Template — Multi-Agent Orchestration]]
> Ready-to-fill template with infrastructure paths, auth injection, agent assignments (A1-A5), phased execution, coordinator protocol, and escalation. Fill `{{TARGET_NAME}}` and `{{SCOPE_TYPE}}` to deploy.

## Per-Target Tracking

Every target gets two files:
- **plan.md** — full Hacker-Harness execution context (scope, auth, tools, skills, agents)
- **progress.md** — R1-R13 + E1+E2 status tracker (R14-R20 tracked separately as context-dependent), updated after each step

## Data Flow

[[methodology/recon-data-flow|Recon Framework — Complete Data Flow Diagram]]
> Producer→Consumer dependency map showing which files each step produces and which steps consume them.

## Hacker-Harness Workflows

[[methodology/genpentest-hh-workflow|GenPentest HH Workflow]]
> File-gated GenPentest stages (P0–P7) for Hacker-Harness chat mode (`/use genpentest`). Plans on disk; `spawn_agent` receives plan paths only.

[[methodology/playwright-mcp-p0-flow|P0 Auth Setup — Playwright MCP]]
> Browser-based registration / SSO / session capture into `ps_tokens.txt`.

## DRF Patterns

[[methodology/drf-pentest-patterns|Django REST Framework Pentest Patterns]]
> Reusable patterns: read/write auth divergence, bulk action IDOR, protocol smuggling SSRF, zero-HTML XSS, event feed BOLA, webhooks, cross-account validation, session death handling.

## Access Control Testing

[[methodology/access-control-testing|Access Control Testing for DRF]]
> Cross-account write IDOR, config manipulation, function-level access control, OAuth misconfigs, method tampering — generic DRF checklist.

## Cross-Account Testing

[[methodology/cross-account-session-testing|Cross-Account Session Testing]]
> How to test IDOR/BOLA across accounts on Cloudflare-protected targets. Cookie forwarding, browser headers, session death patterns.

## SSRF Testing

[[methodology/ssrf-testing|SSRF Testing Methodology]]
> Protocol smuggling, webhook-based SSRF, cloud metadata targets, blind SSRF confirmation via OOB callbacks.

## General Pentest Framework

[[methodology/gen-pentest-framework|General Pentest Framework — Auth-Injected, Role-Aware, Multi-Tenant]]
> Multi-phase pipeline (P0–P7) with Hacker-Harness orchestration: app understanding, public index, JS/API analysis, client-side bugs, role matrix, business logic, cross-org. Plans written after discovery; findings verified before `Vulnerabilities.md`.

## Data Flow (GenPentest)

[[methodology/genpentest-data-flow|GenPentest Data Flow]]
[[methodology/genpentest-data-flow-diagram|GenPentest Data Flow Diagram]]
> Artifact contracts between phases (`ps_tokens.txt`, `APIendpoint.md`, plans, findings).
