# TrustOS — Agent Working Guide

Read this before touching code. The specs are [prd.md](prd.md) (what and why) and
[architecture.md](architecture.md) (how). This file is the short version plus the rules
that are easy to violate by accident.

## What this is

An enterprise control layer for AI agents. It identifies an agent, binds it to an
accountable human owner, bounds its capabilities, evaluates each individual action
request against deterministic policy, routes sensitive actions to a human approver, and
issues a **short-lived single-use execution grant** that a customer-controlled gateway
consumes before it touches the destination system (a CRM, in the first release).

TrustOS never executes the business action itself. It decides and records authority. The
gateway executes, using its own destination credentials.

**Current state: design only.** No application code, no infrastructure, no git repo yet.
Everything below is the plan, not a description of what exists.

## Non-negotiable invariants

These are correctness, not style. A change that breaks one of these is a bug even if
tests pass. If a task seems to require breaking one, stop and raise it.

1. **Fail closed.** If identity, policy integrity, current authority, or the durable
   write cannot be established, return an error. Never degrade to permissive behavior.
   There is no fail-open mode, no "temporary" bypass flag, no cached-allow fallback.
2. **PostgreSQL is the source of truth** for approvals, idempotency, grants, consumption
   receipts and audit. Redis is a rate limiter and an immutable-bundle cache. Never read
   from Redis to decide whether an approval exists, a grant is unconsumed, or an identity
   is active.
3. **A decision is not permission to execute.** Only a grant, consumed online in a
   database transaction, authorizes a protected write. Never return an executable grant
   on a non-2xx response, from a simulation, or in shadow mode.
4. **One consume per grant, ever.** Consumption locks the grant row, rechecks every
   epoch and the current bundle revision, and writes a unique receipt in the same
   transaction. A lost response is recovered by replaying the same gateway + execution
   key, which returns the original receipt. It is never a second grant.
5. **Tenant and environment come from the authenticated token**, resolved server-side.
   Never from a request body, query param, header hint, or anything the caller supplies.
   Mismatched hints are rejected, not honored.
6. **Audit and outbox rows are written in the same transaction as the mutation.** If the
   audit insert fails, the mutation fails and nothing is acknowledged. Never insert audit
   after commit, never "best effort" it, never move it to a queue.
7. **No LLM, no `eval`, no dynamic code, no network calls on the policy path.** The
   evaluator is pure TypeScript over a typed restricted DSL with bounded inputs. Same
   bundle + same evaluator version + same normalized snapshot must produce byte-identical
   effect, reasons and obligations.
8. **Deny precedence.** Validation and identity and capability checks, then emergency
   stops, then explicit deny, then approval_required, then allow, then default deny. A
   missing field, type mismatch or error never becomes an allow.
9. **Published policy is immutable.** Rollback is a new publication with a new revision.
   Publishing a revision invalidates all unconsumed grants under the old one.
10. **Money is integer minor units plus an explicit currency. Discounts are integer basis
    points.** No floats anywhere near an amount, a threshold or a comparison.
11. **Expiry is checked against server/database time**, in UTC, at resolution and at
    consumption. A delayed scheduler never extends a deadline.
12. **Untrusted input stays untrusted.** Agent-supplied purpose text, business reason, or
    a self-reported risk score can never establish an access right. Trusted attributes
    come from TrustOS records or from the gateway's read of a permitted destination, with
    provenance and `observed_at` recorded.
13. **Never log or persist** bearer tokens, client secrets, signing keys, raw prompts, or
    full customer payloads. Mask before serialization, not after.

## Stack

TypeScript everywhere. NestJS backends, React + Vite + MUI console, Prisma plus reviewed
raw SQL over PostgreSQL, Redis for rate limits and immutable caching, BullMQ as a
dispatch hint over a PostgreSQL outbox. OIDC provider for auth; managed KMS and secret
store. OpenAPI 3.1 is the contract source and generates SDK types.

Pin versions after a compatibility and security review. The specs deliberately do not
name versions; do not invent them.

## Repository layout

```
apps/console          React UI
apps/control-api      org, identity, policy, approval, audit routes
apps/decision-api     authorize, decision read, grant consume, outcome
apps/worker           outbox, webhook, expiry, export, integrity, reconciliation
packages/domain       invariants and state transitions
packages/policy-engine  schema, compile, evaluate, explain (pure)
packages/contracts    OpenAPI source, request and event schemas
packages/database     Prisma schema, SQL migrations, repositories, tenant transactions
packages/auth         token validation and guards
packages/observability  safe logging and metrics helpers
packages/sdk-typescript
integrations/reference-crm   trusted gateway adapter and sandbox destination
tests/security tests/load tests/e2e
infra docs/runbooks
```

**One module owns writes to each table.** Other modules call its domain interface, never
its tables. Enforce this with import rules, not convention. See architecture.md §4 for
the ownership map.

## Build order

Follow architecture.md §16. Each step depends on the one before it:

1. Contracts, action taxonomy, trust-boundary threat model
2. Tenant transactions, RLS, membership and provider auth
3. Agent ownership, credentials, epochs, suspension
4. Capability bounds, policy compiler, review and publication
5. Decision ledger, idempotency, transactional audit and outbox
6. Online grants, gateway adapter, outcomes
7. Approval resolution and pending UI
8. Webhooks, evidence export, health, safe retries
9. SDK, reference CRM, developer quickstart
10. Load, security and restore drills; staged pilot

**Do not defer audit insertion, grant consumption or tenant isolation to "after the happy
path works."** They are part of the happy path's correctness. Console work may proceed
against versioned contracts while backend modules land.

## Conventions

- `/v1` JSON over HTTPS. `Authorization: Bearer`, `Idempotency-Key` on business
  mutations, `X-Request-ID` for tracing.
- A valid authorization returns **200 for every effect**, including `deny` and
  `approval_required`. Non-2xx means a technical failure and carries no authority.
- Errors use stable machine-readable codes. See architecture.md §9.5 for the table
  (`INVALID_SCHEMA`, `CALLER_SCOPE_DENIED`, `IDEMPOTENCY_CONFLICT`, `GRANT_EXPIRED`,
  `AUTHORITY_STALE`, `GRANT_ALREADY_CONSUMED`, `DURABLE_STORE_UNAVAILABLE`, …). Do not
  invent new codes without adding them to the contract.
- 404 for cross-tenant objects. Never disclose that another tenant's ID exists — not in
  an error message, a timing difference, or an export.
- Cursor pagination, default 50 and max 200. No unbounded offsets.
- UTC ISO timestamps. Opaque IDs.
- Idempotency is a PostgreSQL unique constraint on
  `(tenant, environment, caller, route, key_hash)`. Same key + same normalized body
  returns the original response; same key + changed body returns 409.
- Canonical request hashing has a fixed schema version, excludes transport trace IDs,
  distinguishes absent from null, and rejects duplicate JSON keys.
- Transactions: acquire authority locks in a fixed order, keep them short, bound the
  conflict retry, and **never call an external API while holding one**.

## Testing expectations

A step is not done until architecture.md §15's layers pass for it. In particular:

- **Database integration tests run as an actual non-owner role** with RLS forced.
  Testing RLS as the table owner proves nothing.
- **Concurrency tests are required**, not optional: concurrent idempotency, approve vs
  reject race, consume replay, publish vs consume, suspend vs consume.
- **Property tests on the evaluator** for determinism, missing context, type mismatch,
  threshold boundaries and obligation conflicts.
- The end-to-end acceptance suite in prd.md §18 is the definition of correct. Treat each
  row as a test case.

CI order: format and lint → typecheck → unit → migrations and isolation → contracts →
integration and security → build and scan → staging → load and e2e.

Database changes use expand / migrate / contract. Control API, decision API and workers
must stay compatible across a rolling deploy.

## Requirement IDs

The PRD uses stable IDs (`ORG-01`, `IDN-04`, `POL-05`, `AUT-07`, `APR-02`, `AUD-01`,
`OPS-01`, `SEC-01`, `NFR-03`, …). Reference them in commit messages, PR descriptions and
test names so coverage stays traceable. When you implement or change behavior tied to an
ID, say which one.

## What is out of scope

Do not build, and do not let scope drift toward: agent builders or model hosting; payment
or refund execution; aggregate spend budgets; multi-stage or quorum approval;
cross-organization delegation; public reputation scores; blockchain or tokens; native
mobile apps; a connector marketplace; SIEM or SCIM integration. These are named in
prd.md §3.4 and §19 as later or never. If a task appears to need one, flag it.

## Decisions

### Settled

| Decision | Choice | Consequence |
| --- | --- | --- |
| Build model | Built entirely by Claude Code across 5 parallel agent tracks, split by write-ownership boundary | No two tracks write the same tables. See "Agent tracks" below. |
| Local scope | Full system: backend, console, SDK, gateway and fake CRM all working locally before UAT | Console track runs beside the backend rather than queued after it |
| Local identity | Keycloak in Docker | Real OIDC: auth-code + PKCE, client-credentials, MFA claims, JWKS rotation. Do not stub token validation. |
| UAT target | Docker Compose on a provided VM | Accepted limit: no synchronous multi-zone failover, so NFR-06 durability and NFR-07 RPO/RTO **cannot** be demonstrated at UAT. Do not report them as met. |
| Review cadence | Sign-off at each wave boundary | Stop and report at the end of each wave; do not roll into the next one unprompted. |

### Still open

Unconfirmed. Do not hardcode as if agreed: production cloud provider and region,
production identity provider, retention periods, TTLs (proposed: 10 minutes approval,
60 seconds grant), SLO commitments, and the first partner's action list.

Latency, capacity and retention figures in the specs are proposed targets awaiting
benchmarks. Never quote them as measured, and never as customer commitments. Local and
Compose-on-a-VM numbers are not evidence for any NFR.

## Agent tracks

| Track | Owns | Depends on |
| --- | --- | --- |
| A1 Core & Data | `packages/contracts`, `packages/database` (schema, RLS, tenant tx), `packages/domain` | — (blocks all others) |
| A2 Policy | `packages/policy-engine`, capabilities, policy routes | A1 contracts |
| A3 Decision & Enforcement | `apps/decision-api`, authorize, grants, consume, outcomes, audit/outbox writes | A1 schema |
| A4 Platform | `packages/auth`, identity & credentials, `apps/worker`, local Docker env | A1 contracts |
| A5 Surfaces | `apps/console`, `packages/sdk-typescript`, `integrations/reference-crm` + fake CRM | A1 contracts (stubs first) |

Integration, concurrency, security and e2e suites are **not** delegated to a track. They
exist to catch mistakes between tracks, so a single track must not author its own.

## Wave plan

| Wave | Content | Gate |
| --- | --- | --- |
| 0 | Repo scaffold, toolchain, CI skeleton, contracts v0, trust-boundary threat model | Contracts reviewed; CI green on an empty build |
| 1 | DB schema, RLS, tenant transactions, auth, local Docker env | RLS proven under a real non-owner role; isolation tests pass |
| 2 | Policy engine, decision core + idempotency, identity lifecycle, SDK | Deterministic evaluation; concurrent idempotency holds |
| 3 | Grants/consume/outcomes, publish + review, console, workers, gateway | Allow and deny paths end to end through the gateway |
| 4 | Approvals end to end, concurrency/security/e2e suites, hardening | prd.md §18 acceptance suite green |
| 5 | UAT deploy on the VM, minimal-usage smoke | Smoke pass; NFR limits stated, not claimed |
