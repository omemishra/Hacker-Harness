## P0 — Auth Setup (Playwright MCP with Firefox)

**Browser:** Firefox (via `--browser firefox` flag). More stable than chromium for SSO redirect chains.

**Primary tool:** `mcp_playwright_browser_run_code_unsafe` for complex SSO/SPA flows (redirect chains, overlays, programmatic checkbox dispatch). For simple forms on static pages, native tools (`browser_navigate` → `browser_snapshot` → `browser_type` / `browser_click`) work and are preferred — element `target` values (refs, `#id`, `xpath=…`) are **not** scope-checked as hostnames.

### Complete Registration Flow (SSO + SPA)

Each step is a single `mcp_playwright_browser_run_code_unsafe` call. Adapt selectors to the target IdP / app UI.

```
1. Navigate to target:
   async (page) => { await page.goto('https://example.com'); }

2. Accept cookies/privacy banner (if present):
   async (page) => { await page.getByRole('button', { name: 'Accept All Cookies' }).click(); }

3. Click "Create account" / "Sign up":
   async (page) => { await page.getByRole('link', { name: 'Create account' }).click(); }

4. Select region (if required):
   async (page) => { await page.getByRole('radio', { name: 'United States (US)' }).click(); }
   async (page) => { await page.locator('#sign-up-button').click(); }

5. Fill registration form:
   async (page) => {
     await page.getByRole('textbox', { name: 'First Name' }).fill('Test');
     await page.getByRole('textbox', { name: 'Last Name' }).fill('User');
     await page.getByRole('textbox', { name: 'Email' }).fill('tester+tag@example.com');
     await page.keyboard.press('Tab');
   }

6. Check terms checkbox (programmatic dispatch — bypasses React overlay issues):
   async (page) => {
     await page.locator('#tc_check').dispatchEvent('change', { bubbles: true });
   }

7. Submit registration:
   async (page) => { await page.getByRole('button', { name: 'Agree and continue' }).click(); }
   → Sends verification code to email

8. STOP — Ask operator for code. Do NOT navigate away.

9. Enter code and submit:
   async (page) => {
     await page.getByRole('textbox', { name: 'Code' }).fill('{user_code}');
     await page.keyboard.press('Tab');
     await page.getByRole('button', { name: 'Submit' }).click();
   }

10. Set password (use engagement test password from operator / scope notes):
    async (page) => {
      await page.locator('input[name="new_password"]').fill('TestPass@12345');
      await page.locator('input[name="confirm_password"]').fill('TestPass@12345');
      await page.keyboard.press('Tab');
      await page.getByRole('button', { name: 'Continue' }).click();
    }

11. Skip optional passkey / MFA enrollment when allowed:
    async (page) => { await page.getByRole('link', { name: 'Skip for now' }).click(); }

12. Navigate to target again → auto-SSO redirect:
    async (page) => { await page.goto('https://example.com'); }
    → Lands on profile completion or home / app page
```

### Token Extraction

```javascript
// After login, extract ALL cookies including HttpOnly
async (page) => {
  return JSON.stringify(await page.context().cookies());
}

// Look for session cookies, CSRF / XSRF tokens, and any auth headers in network responses
```

Save full (non-truncated) values to `ps_tokens.txt` as a curl-compatible `Cookie:` / header block.

### Pitfalls

- **2FA / MFA / Email OTP Hard Stop:** When a verification code / OTP screen appears ("Complete your sign in", "Enter verification code", "Enter OTP"):
  - **HARD STOP** immediately and request the live OTP code from the operator.
  - **NEVER** search project history / past runs for old OTP codes (OTPs are dynamic single-use tokens).
  - **NEVER** navigate away, reload, or test stale cookies.
  - Enter the code given by the operator directly into the active browser page and submit.
- **CRITICAL on Redirects:** Do NOT interrupt auth redirects mid-way to inspect cookies/page state — this destroys the OAuth state token and restarts everything.
- **Dismiss ALL dialogs** before filling forms (privacy/cookie consent blocks interactions)
- **Click EVERY optional "Skip" enrollment option** — click "Skip for now" / "I'll enable MFA later" ONLY when prompted to enroll optional MFA or passkeys (do not confuse with mandatory login OTP challenges).
- **Only capture cookies AFTER page loads with a stable URL** — brief page loads during redirect chain are not final
- **Checkbox click fails via a11y tree** — use `page.locator('#id').dispatchEvent('change')` instead of `.check()`
- **Tab key to enable disabled buttons** — SSO forms require blur event before buttons become clickable
- **Subdomain redirects** — Firefox handles SSO redirect chains better than chromium
- **30s click timeouts** — use `{ force: true }` to bypass overlays:
  `await page.locator('#sign-up-button').click({ force: true });`
- **About:blank collapse** — re-navigate with `page.goto(target_url)`. SSO tokens in URL are still valid.
