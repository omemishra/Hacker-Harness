# Cross-Account Session Testing on Cloudflare-Protected Targets

## The Problem

When testing IDOR/BOLA on Cloudflare-protected targets, browser-exported session cookies often expire when used from curl. The server detects IP/User-Agent mismatches and clears the `sessionid` cookie (returning `sessionid=""` in response headers). Once killed, the Django session is permanently dead — even fresh Cloudflare cookies (`__cf_bm`, `_cfuvid`) don't revive it.

## Required Cookies

A browser-exported cookie set is useless unless you send ALL of these together:

| Cookie | Source | Purpose |
|--------|--------|---------|
| `sessionid` | Django | User authentication — THE critical one |
| `csrftoken` | Django | CSRF protection for mutating requests |
| `__cf_bm` | Cloudflare | Bot management — short-lived (~30 min) |
| `_cfuvid` | Cloudflare | Visitor ID — session-scoped |
| `_internal_traffic` | App-specific | Sometimes needed for internal routing |

## Required Headers

Always set browser-matching headers:

```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0
Accept: application/json
Referer: https://target.com/
Origin: https://target.com/   (for CORS requests)
```

## Session Death Pattern

If the server returns `sessionid=""` in a `Set-Cookie` response header, your session is dead. This happens when:
- Curl is used from a different IP than the browser
- User-Agent doesn't match the browser
- Too many parallel requests trigger anti-abuse controls
- A mutating endpoint (POST/PATCH/DELETE) with invalid CSRF token triggers session invalidation

**Once dead, it cannot be revived.** Get a fresh session from the browser.

## Testing Workflow

1. **Export cookies** from browser as JSON
2. **Extract** sessionid, csrftoken, __cf_bm, _cfuvid, _internal_traffic
3. **Set browser headers** (UA, Accept, Referer)
4. **Verify session** with `GET /api/v1/auth/user/` — expect 200 with user data
5. **Run ALL cross-account tests in one batch** — don't pause between calls
6. If session dies mid-test, discard results and start over with fresh cookies

## Cross-Account Test Matrix (8 Permutations)

| # | Account | Resource | Endpoint | Expected |
|---|---------|----------|----------|----------|
| 1 | A | A's resource | LIST | 200 (baseline) |
| 2 | A | B's resource | LIST | 403 or empty |
| 3 | A | B's resource | READ detail | 404 |
| 4 | A | B's resource | PATCH | 404 or 403 |
| 5 | A | B's resource | DELETE | 404 or 403 |
| 6 | B | A's resource | LIST | 403 or empty |
| 7 | B | A's resource | READ detail | 404 |
| 8 | B | A's resource | PATCH | 404 or 403 |

**For mutating requests (PATCH/DELETE):** Always include `X-CSRFToken: <csrftoken>` header and `Content-Type: application/json`.
