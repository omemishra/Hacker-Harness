---
name: mobile-apk-decompilation-audit
description: Android APK decompilation, jadx static analysis, hardcoded secret grep, exported activity/intent hijacking, and insecure deep link scheme auditing.
playbook: web-security
---

# Mobile Android APK Static Analysis & Secret Extraction

## Attack Vector Summary
Mobile APK auditing involves acquiring target Android applications, decompiling `.apk` archives into readable Java/Kotlin source code via `jadx`, and analyzing the codebase for hardcoded API keys, private endpoints, insecure cryptographic implementations, exported component intent hijacking, and unvalidated deep link schemes.

## Tactical Heuristics & Step-by-Step Flow

### 1. APK Acquisition & Decompilation
```bash
# Decompile APK with jadx (generating Java sources and AndroidManifest.xml)
jadx -d /tmp/apk_extracted target_app.apk
```

### 2. High-Risk Secret Grep Patterns
Search decompiled sources and `res/values/strings.xml` for embedded keys:
- Cloud keys: `AKIA[0-9A-Z]{16}`, `AIzaSy[0-9A-Za-z-_]{33}` (Firebase / Google API), `sk_live_[0-9a-zA-Z]{24}`
- OAuth Client Secrets, private encryption keys (`AES`, `DES`), internal backend staging URLs (`https://api-staging.target.com`).

### 3. AndroidManifest.xml Component Audit
Check for exposed exported components without permissions:

```xml
<!-- 1. Insecure Exported Activity: -->
<activity android:name=".admin.AdminDebugActivity" android:exported="true"/>

<!-- 2. Exported Broadcast Receiver / Service: -->
<receiver android:name=".receivers.TokenRefreshReceiver" android:exported="true"/>

<!-- 3. Insecure Deep Link Schemes: -->
<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="targetapp" android:host="auth_callback"/>
</intent-filter>
```

### 4. Deep Link & WebView JavaScript Interface Audit
- Check if custom deep links (`targetapp://auth_callback?token=...`) can be hijacked by third-party malicious apps.
- Check WebViews for `addJavascriptInterface` or disabled `setAllowFileAccess(true)`.

## Empirical Disclosed Report Patterns & High-Risk Matrices
| Vector / Pattern | Mechanism | Empirical Pattern | Expected Evidence Marker |
|---|---|---|---|
| Leaked Production Secret in Strings | Developer leaves Stripe live secret key in XML | `sk_live_...` in `res/values/strings.xml` | Verified active charge capability on payment gateway |
| Unauthenticated Admin Activity | Debug activity exported without permission check | `android:exported="true"` on `.DebugActivity` | ADB launch `am start -n app/.DebugActivity` reveals admin UI |
| Insecure Deep Link Token Leak | Deep link receives auth token without state validation | `targetapp://sso?access_token=...` | Third-party app registers same scheme to capture token |

## Evidence Collection & Validation Gate
- Cite exact file path (e.g. `res/values/strings.xml:42` or `com/target/api/ApiClient.java:108`).
- Verify live validity of extracted secrets or reproduce intent launch with `adb shell am start`.
- Evaluate against `/validate` 7-Question Validation Gate before reporting.
