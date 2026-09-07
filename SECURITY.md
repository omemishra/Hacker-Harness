# Security policy

## Operating boundaries

Hacker-Harness is intended only for authorized security testing and defensive engineering. Keep written authorization, program rules, rate limits, dates, permitted techniques, and exclusions outside the harness as the authoritative record. Reflect those limits in `.hacker-harness/scope.yaml`.

## Guardrails

- Paths are resolved and restricted to the initialized project root.
- Strict mode requires interactive confirmation for every shell command.
- Known network-capable tools require an active scope and explicit in-scope targets.
- Exclusions override target inclusions.
- Common destructive command forms are blocked.
- Tool calls and decisions are recorded in `.hacker-harness/state.db`.
- Model file tools cannot read operator-controlled scope, settings, state, system-prompt, or history files; a sanitized runtime summary supplies required status instead.
- The project sends no telemetry.
- Provider profiles store `${ENVIRONMENT_VARIABLE}` references, never raw API keys; literal `apiKey` values are rejected.

Interactive conversation history, tool results, and structured findings may contain sensitive engagement data. They are stored locally in `.hacker-harness/state.db`; Hacker-Harness sets user-only file permissions. Protect the project directory, avoid committing `.hacker-harness`, and remove engagement state according to program retention requirements.

The native `http_request` tool validates the initial hostname against active scope, requires approval in strict mode, and deliberately does not follow redirects. Sensitive header names such as `Authorization` and `Cookie` are redacted from audit arguments.

MCP servers are external local processes and therefore a separate trust boundary. Server startup and tool calls require approval by default. Common target-like arguments are scope checked, but a server can perform opaque internal behavior; configure only trusted servers and retain OS-level isolation.

## Limitations

This is not a complete sandbox or policy engine. Shell wrappers, interpreters, custom binaries, DNS changes, redirects, and tool behavior can defeat simple command inspection. Run in a dedicated non-root container or VM, isolate credentials, restrict egress, keep backups, and review commands before approval. Do not place API keys in project files or model prompts.

## Reporting a vulnerability

Do not include real secrets, live customer data, or third-party targets in reports. Provide a minimal local reproduction, affected version, impact, and proposed remediation through the repository's private security-reporting channel.
