---
name: web-concurrency-race-condition
description: Web concurrency and race condition assessment, single-packet attack synchronization, limit-overrun testing, gift card / coupon double spending, and TOCTOU state machine abuse.
---

# Concurrency & Race Condition Security Assessment

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Verified target business workflows (payments, voucher redemptions, voting, invitations, password resets) in `scope.yaml`.
- **Target Parameters:** Endpoints that read state, perform validation, and then mutate database balances or states.
- **Traffic Routing:** Route synchronized burst requests through Caido proxy or Python concurrent `asyncio` client with connection warming.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: Identifying Concurrency Vulnerable State Transitions
Look for non-atomic read-then-write operations:
1. **Limit-Overruns:** Redeeming a single-use promo code multiple times simultaneously.
2. **Double-Spending:** Transferring or withdrawing funds faster than the ledger balance is decremented.
3. **Multi-Invite Privesc:** Inviting multiple high-privilege users concurrently when organization seats are capped.
4. **Password Reset Token Reuse:** Using a single-use password reset token across 10 simultaneous requests to set multiple valid passwords.

### Step 2: Single-Packet Attack & Microsecond Synchronization
In HTTP/2 or multiplexed HTTP/1.1 connections:
1. Open a single TCP connection with TLS negotiation completed.
2. Send all HTTP request headers in advance (warm up the connection).
3. Send the final small payload byte of 20–50 parallel requests in a **single TCP packet** so they arrive at the application server in the exact same millisecond window.

```python
# Synchronized asyncio probe template
import asyncio
import httpx

async def burst_probe(target_url, headers, payload, count=20):
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        # Pre-warm connection
        await client.get(target_url)
        tasks = [
            client.post(target_url, headers=headers, json=payload)
            for _ in range(count)
        ]
        responses = await asyncio.gather(*tasks)
        statuses = [r.status_code for r in responses]
        print(f"Burst responses: {statuses}")
```

### Step 3: TOCTOU (Time-of-Check to Time-of-Use) Verification
Observe whether multiple requests succeed (HTTP 200) instead of only one succeeding (HTTP 200) and the rest failing (HTTP 400/409 "Already redeemed"):
```http
POST /api/v1/coupon/apply HTTP/2
Host: target.example.com
Authorization: Bearer {{ token }}
Content-Type: application/json

{"code": "DISCOUNT100"}
```

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Workflow Context | Concurrency Flaw | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **Gift Card Redemption** | Balance check occurs before balance debit without database lock | Send 30 simultaneous `/redeem` requests for a $10 card | Account credited with $300 balance |
| **Email Change Verification** | Verification token validated, but multiple accounts claim it | Parallel verification requests with different user sessions | Attacker claims victim email identity |
| **2FA Rate-Limit Bypass** | Counter increment is not atomic | Send 1,000 2FA OTP guesses in parallel burst | Rate limit counter only records 5 attempts; OTP cracked |
| **File Upload Race Condition** | File saved to temporary directory before virus scanning/deletion | Request temporary file path `/uploads/temp/shell.php` during upload window | Shell executes before cleanup routine deletes it |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture logs of parallel requests showing identical timestamps ($\pm 5\text{ms}$), multiple successful HTTP 200 responses, and the resulting anomalous state (e.g. multiple credits or double execution).
2. **Impact Proof:** Verify limit overrun using benign test values (e.g. 2 coupon redemptions instead of mass exploitation).
3. **Remediation:** Enforce database transactions with row-level locking (`SELECT FOR UPDATE`), implement atomic increments/decrements, use distributed mutexes (e.g. Redis Redlock), or utilize unique database index constraints.
