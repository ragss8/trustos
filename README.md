# TrustOS

An enterprise control layer for AI agents. TrustOS identifies an agent, binds it to an
accountable human owner, bounds its capabilities, evaluates every action request against
deterministic policy, routes sensitive actions to a human approver, and issues a
short-lived single-use execution grant that a customer-controlled gateway consumes before
touching the destination system.

TrustOS never executes the business action. It decides and records authority; the gateway
executes using its own destination credentials.

## Documents

| File                                         | Purpose                                                         |
| -------------------------------------------- | --------------------------------------------------------------- |
| [CLAUDE.md](CLAUDE.md)                       | **Read first.** Invariants, build order, conventions, decisions |
| [prd.md](prd.md)                             | Product requirements v1.1 — requirement IDs, acceptance suite   |
| [architecture.md](architecture.md)           | Implementation design v1.0 — schema, flows, API contract        |
| [docs/threat-model.md](docs/threat-model.md) | Trust boundaries and the attacks each control addresses         |

## Status

Waves 0–3 complete. The full control path runs locally end to end.

```
agent -> gateway -> TrustOS decides -> [human approves] -> single-use grant
      -> gateway consumes it once -> CRM updated -> outcome recorded
```

| Component                             | State                                     |
| ------------------------------------- | ----------------------------------------- |
| Tenant isolation, schema, audit chain | 28 tables, proven under a non-owner role  |
| Token validation                      | Against real Keycloak                     |
| Policy engine                         | Deterministic, machine-enforced purity    |
| Decision core + idempotency           | 16 concurrent requests yield one decision |
| Agent lifecycle + containment         | Epoch-based revocation                    |
| Grants + single-use consumption       | Two racing gateways yield one receipt     |
| Approvals                             | Separation of duties, server-time expiry  |
| Decision + control APIs               | Serving HTTP                              |
| Reference gateway + fake CRM          | Durable operation ledger                  |
| Console                               | Approvals, registry, audit, overview      |
| Hardening, full §18 suite             | Wave 4                                    |

250 automated tests.

## Getting started

```sh
pnpm install
pnpm db:up          # postgres + redis on offset ports (5432/6379 are commonly taken)
pnpm db:migrate     # apply packages/database/db/*.sql
docker compose up -d keycloak
pnpm verify         # format, lint, typecheck, boundaries, test
```

`pnpm db:reset` rebuilds the database from an empty volume. Migrations are checksummed:
editing an applied one is refused, because that is how environments silently diverge.

Requires Node 26 and pnpm 11. TypeScript is pinned to the 6.x line: TypeScript 7 is not
yet supported by typescript-eslint or dependency-cruiser, and losing boundary enforcement
costs more than the compiler speed gains.

## Layout

```
apps/console          React UI
apps/control-api      org, identity, policy, approval, audit routes
apps/decision-api     authorize, decision read, grant consume, outcome
apps/worker           outbox, webhook, expiry, export, integrity, reconciliation
packages/*            contracts, domain, policy-engine, database, auth, observability, sdk
integrations/         reference CRM gateway and fake destination
tests/                security, load, e2e
```

Module boundaries are machine-enforced by `pnpm boundaries`, not by convention.
