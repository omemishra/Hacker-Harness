# Recon Framework — Quick Reference
## R1-R20 + E1+E2 | SCOPEONLY vs WILDCARD

### CORE RECON
| Step | Tool | Key Output | Feeds |
|------|------|-----------|-------|
| R1 | curl | target_sensitive_files.txt | — |
| R2 | katana | target_katana.txt | R7 |
| R3 | gau + wayback | target_gau.txt, target_wayback.txt | R4, R7 |
| R4 | grep + curl | GW_emails.txt, GW_live_tokens.txt, GW_files.txt, GW_dotfile.txt | — |
| R5 | getJS + jsluice | target_endpoints.txt, jsbundles/*.js | R7, R12 |
| R6 | getJS | target_recovered_sources.txt | — |
| R7 | Arjun + qsreplace | gwjs_endpoints→Arjun→mined_pendpoint→GWJSAJQ_urls.txt | R11, R13 |
| R8 | whatweb | target_whatweb.txt | E2 |
| R9 | curl + CSPBypass DB | target_csp_bypass_payloads.txt | R11 |
| R10 | OpenRedirex | GW_open_redirect + AQ_redirect → P_O_Redirect → findings | — |
| R11 | XSStrike | on GWJSAJQ_urls.txt → psqli.txt | E1 |
| R12 | grep + curl | prototype pollution test output | — |
| R13 | ssrfmap + interactsh | target_oob.txt | — |

### GITHUB RECON
| Step | Tool | Key Output |
|------|------|-----------|
| R14a | Github_Brute-Dork + Github-Dorks + github-search | target_gh_dorks.txt |
| R14b | Manual dorking (1,592 keywords + 90 dorks) | target_gh_dorks.txt |
| R14c | trufflehog + gitleaks + medusa | target_trufflehog.txt |
| R14d | PR/Commit/Issue scan | target_gh_pr_leaks.txt, target_gh_commit_leaks.txt |

### CODE REVIEW (R15)
| Step | Tool | When |
|------|------|------|
| R15.1 | grep secrets | Always |
| R15.1 | Bandit | Python only |
| R15.1 | Semgrep (14 langs) | Always |
| R15.2 | Supply chain detect | Always — typosquatting, dep confusion, CI/CD actions, install scripts |
| R15.3 | Hacker-Harness | Always — independent review |
| **All R** | Report format | Every finding: URL + line + 5-10 line snippet |

### OPTIONAL RECON
| Step | Tool | Key Output |
|------|------|-----------|
| R16 | rustscan / naabu | target_ports.txt |
| R17 | feroxbuster / ffuf | target_ferox.txt |
| **MANDATE** | ALL R1-R17 must run — never skip. Evidence N/A, don't assume. Missing tool = install or manual equivalent. Verify all phases in publicindex.md. |
| R18 | gobypass403 | bypass results |
| R19 | curl -H "Origin: evil.com" | CORS check |
| R20 | crt.sh | target_crtsh.txt |

### EXPLOITATION
| Step | Tool | Trigger |
|------|------|---------|
| E1 | BSQLi 2.0 → sqlmap | psqli.txt (R11) |
| E2 | PayloadsAllTheThings | ptLFI.txt (R7) |

### DATA FLOW
```
R3 gau/wayback ────────────────────────────┐
R5 JS analysis ────────────────────────────┤→ gwjs_endpoints.txt → Arjun
                                            ↓
                                     mined_pendpoint.txt
                                            ↓
                              merge → GWJSAJQ_urls.txt
                                            ↓
                                         R11 XSStrike

R4 gau/wayback ─── responsive analysis
                    ├── GW_emails.txt     (finding: 5+ emails)
                    ├── GW_live_tokens.txt (finding: valid token)
                    ├── GW_files.txt      (finding: accessible file)
                    └── GW_dotfile.txt    (finding: .env/.git)

R10 GW_open_redirect.txt + AQ_redirect.txt → P_O_Redirect.txt → OpenRedirex → findings
```

### ORCHESTRATION
| Agent | Role | Behavior |
|-------|------|----------|
| A0 | Coordinator + Interactive Bridge | Monitors agents, file handoffs, blockers. On interesting findings: suggests options [a/b/c], reports to me, relays decisions |
| **Dependency chains** | Bug-specific | XSS → A1(R3+R4)→A2(R5)→A3(R7)→A4(R11). SQLi → same → E1. See workflow for full matrix |

### SCOPE RULES
- **SCOPEONLY**: NO subfinder/amass/crt.sh. SSO domains NOT in-scope.
- **WILDCARD**: Full subdomain discovery.
- **Ask**: "Shall we start recon (R1-R13 + E1+E2)?"
- **Detail**: "Detailed recon (R1-R20 + E1+E2)?"
- **Bug named**: R1-R9 + R10-R?? focused on that bug.
