# Recon Framework — Complete Data Flow & Dependency Map

## Core Recon

```
R1  Sensitive File Exposure   → target_sensitive_files.txt     [manual review]
R2  katana                    → target_katana.txt              → R5, R7, R12
R3  gau + waybackurls         → target_gau.txt                 → R4, R7
                                target_wayback.txt              → R7
R4  responsive analysis       → GW_emails.txt                  [finding: 5+ email occurrences]
                                GW_live_tokens.txt              [finding: verified live tokens]
                                GW_files.txt                    [finding: accessible CSV/Excel/PDF]
                                GW_dotfile.txt                  [finding: accessible .env/.git/etc]
                                target_secrets.txt              [manual review]
R5  JS bundle analysis        → target_endpoints.txt           → R7 (gwjs_endpoints)
                                target_js_secrets.txt           [manual review]
                                target_postmessage.txt          [manual review]
                                jsbundles/*.js                  → R11 CSPP
R6  Source maps               → target_recovered_sources.txt   [manual review]
R7  Arjun + qsreplace         → gwjs_endpoints.txt (R3+R5 merged base paths)
                                mined_pendpoint.txt (Arjun on gwjs)
                                GWJSAJQ_urls.txt (R3+R3+mined → dedup → R10)
                                target_params.txt (qsreplace extracted)
                                ptLFI.txt                       → E2, R12
R8  whatweb                   → target_whatweb.txt             → E2 (OS detection)
R9  CSP + headers             → target_csp_domains.txt         → CSPBypass lookup
                                target_csp_bypass_payloads.txt  → R11 (re-test XSS)
R10 Open Redirect             → GW_open_redirect.txt (gau/wayback redirect URLs)
                                AQ_redirect.txt (Arjun redirect params)
                                P_O_Redirect.txt (merged → OpenRedirex)
                                P_O_Redirect_findings.txt      [finding: confirmed open redirect]
R11 XSStrike                  → on GWJSAJQ_urls.txt
                                psqli.txt                       → E1
R12 CSPP                      → (test output only)
R13 SSRF                      → target_ssrf_params.txt         → ssrfmap
                                target_oob.txt                  → interactsh
R14 GitHub                    → target_gh_dorks.txt
                                target_trufflehog.txt
                                target_gh_pr_leaks.txt (PR/commit keyword hits)
                                target_gh_commit_leaks.txt (commit credential patterns)
                                target_employees.txt
R15 Code Review               → target_code_review_secrets.txt
                                target_code_review_bandit.txt
                                target_code_review_semgrep.txt
                                target_code_review_medusa.txt
                                target_code_review_supplychain.txt
                                target_code_review_malcontent.json
                                target_code_review.md (HH deep review)
                                target_code_review_report.md (with permalink + snippet)
```

## Optional Exploitation

```
E1  BSQLi 2.0 + sqlmap        ← psqli.txt (R10)
E2  LFI + Path Traversal      ← ptLFI.txt (R7) + whatweb.txt (R8)
```

## Optional Recon (standalone)

```
R14 GitHub recon              → target_gh_dorks.txt, target_trufflehog.txt
R15 Port scanning             → target_ports.txt
R16 Directory fuzzing         → target_ferox.txt               → R17
R17 403/401 bypass            ← target_ferox.txt (R16)
R18 CORS check                → [single request]
R19 crt.sh                    → target_crtsh.txt
```

## Key Dependency Chains

```
Chain 1: R3+R3+R5 → R7 → gwjs_endpoints.txt → Arjun → mined_pendpoint.txt
         → GWJSAJQ_urls.txt → R10 (XSStrike)
Chain 2: R7 → ptLFI.txt → E2 (LFI), R12 (SSRF overlap)
Chain 3: R10 → psqli.txt → E1 (BSQLi → sqlmap)
Chain 4: R9 → CSP bypass payloads → R10 (re-test XSS)
Chain 5: R8 → whatweb.txt → E2 (OS detection for payloads)
Chain 6: R15 → target_ferox.txt → R16 (403 bypass)
Chain 7: R5 → jsbundles/*.js → R11 (CSPP)
```
