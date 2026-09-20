# TrustOS Trust-Boundary Threat Model

| Field  | Value                                                       |
| ------ | ----------------------------------------------------------- |
| Wave   | 0 — initial model, revised at each wave gate                |
| Scope  | Local build. Deployment-specific threats deferred with UAT. |
| Method | Boundary enumeration, then per-boundary attacker goals      |

This model exists to justify controls, not to catalogue every vulnerability. Each control
in [CLAUDE.md](../CLAUDE.md) traces to a row here. If a control has no threat, it is
ceremony and should be deleted; if a threat has no control, it is accepted risk and must
be named as such.

## 1. Trust domains

| Domain                             | Trusted for                                                                                                                                                    | Never trusted for                                                                                         |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **Agent runtime**                  | Nothing. It is the subject of the system.                                                                                                                      | Its own identity claim, purpose text, risk self-assessment, region, or any attribute affecting a decision |
| **Enforcement gateway** (customer) | Authenticating the agent upstream, attesting which agent it represents, reading resource state from permitted destinations, executing with its own credentials | Representing agents outside its allowlist; asserting that policy was satisfied                            |
| **TrustOS control plane**          | Deciding and recording authority                                                                                                                               | Executing business actions; proving a destination write happened                                          |
| **Destination** (CRM)              | Being the system of record for business data                                                                                                                   | Enforcing TrustOS policy; providing idempotency unless verified                                           |
| **Console user**                   | Actions their current server-side role permits                                                                                                                 | Any authority carried in a client-side claim                                                              |

The gateway is the pivotal boundary. **If an agent holds destination credentials directly,
TrustOS is decorative** — every control below is bypassed by not calling it. This is the
single assumption the whole design rests on, and it is a deployment property TrustOS
cannot verify from its own logs (prd.md §13 requires comparing destination logs).

## 2. Attacker goals and controls

### 2.1 Execute an unauthorized action

| Attack                                          | Control                                                                                                                             | Trace               |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| Call the destination directly, skipping TrustOS | Destination credentials live only at the gateway; egress restrictions; coverage measured against destination logs, not TrustOS logs | prd.md §17, §13     |
| Replay a grant to execute twice                 | Single durable consumption per grant under row lock; unique receipt                                                                 | INVARIANT 4, AUT-07 |
| Present a grant to the wrong gateway            | Grant bound to gateway audience and exact request fingerprint                                                                       | AUT-07              |
| Use a grant after suspension                    | Epoch recheck at consume, not only at authorize                                                                                     | OPS-01, NFR-03      |
| Use a grant issued under retired policy         | Bundle revision rechecked at consume; publication invalidates unconsumed grants                                                     | ADR-009             |
| Treat a shadow-mode decision as authority       | Shadow never produces a consumable grant                                                                                            | INVARIANT 3, AUT-08 |
| Treat an approval webhook as permission         | Webhooks are refresh hints; authority is the grant alone                                                                            | architecture.md §2  |
| Escalate via a simulation run                   | Simulation cannot yield consumable grants                                                                                           | POL-04              |

### 2.2 Obtain a favourable decision

| Attack                                                | Control                                                                                             | Trace                     |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------- |
| Assert a permitted region in the request body         | Region is a trusted attribute with provenance and freshness; agent-sourced values cannot satisfy it | INVARIANT 12, §5.3        |
| Prompt-inject a persuasive business reason            | Free text is untrusted and cannot establish access; no LLM on the decision path                     | INVARIANT 7, INVARIANT 12 |
| Send a discount as `"1500"`, `15.0` or `1e3`          | Branded integer basis points; type mismatch is a validation failure, never an allow                 | INVARIANT 10, POL-05      |
| Send an unknown or near-miss action key               | Closed catalog; unknown actions cannot authorize                                                    | POL-01                    |
| Exploit `__proto__` or `constructor` as an action key | Explicit allowlist membership test, not property lookup                                             | POL-01                    |
| Omit a required field hoping rules are skipped        | Missing required context cannot skip restrictive rules; default deny                                | POL-05, §7.2              |
| Race a policy publication                             | Bundle revision read inside the decision transaction under lock                                     | §8.1                      |

### 2.3 Escalate through approval

| Attack                                                | Control                                                                   | Trace     |
| ----------------------------------------------------- | ------------------------------------------------------------------------- | --------- |
| Approve one's own request                             | Separation of duties checked at resolution, not only at routing           | APR-03    |
| Approve after losing eligibility                      | Current membership rechecked at resolution                                | APR-03    |
| Approve an expired request via a delayed notification | Server-time deadline enforced at resolve and at consume                   | APR-01    |
| Double-resolve through a race                         | Compare-and-set on state; first terminal transition wins                  | APR-02    |
| Reuse an approval for a similar later request         | Approval authorizes exactly one request fingerprint                       | prd.md §8 |
| Publish a permissive policy alone                     | Production publication requires an independent reviewer of the exact hash | SEC-01    |

### 2.4 Cross-tenant access

| Attack                                              | Control                                                          | Trace               |
| --------------------------------------------------- | ---------------------------------------------------------------- | ------------------- |
| Supply another tenant's ID in body, query or header | Scope derived from the token; supplied hints rejected            | INVARIANT 5, ORG-01 |
| Reach another tenant's rows via a missed `WHERE`    | Row-level security under a non-owner, non-BYPASSRLS role         | ORG-01, §6.1        |
| Leak scope across a pooled connection               | Transaction-local settings only; never connection-session state  | §6.1                |
| Escape scope inside a background job                | Workers enter the same tenant transaction wrapper                | §6.1                |
| Probe for existence of another tenant's object      | 404 with no existence disclosure, including in errors and timing | §9.5                |
| Attach a valid foreign row ID                       | Composite foreign keys including tenant and environment          | §6.1                |
| Use a sandbox credential against production         | Credentials bound to one principal and environment               | §5.2                |

### 2.5 Destroy or forge evidence

| Attack                                            | Control                                                                                                           | Trace               |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------- |
| Succeed at an action while the audit write fails  | Audit and mutation share one transaction; no audit means no acknowledgement                                       | INVARIANT 6, AUD-01 |
| Edit history in the database                      | Hash-chained append-only events; KMS-signed manifests in separately protected storage                             | AUD-01, §10.2       |
| Rewrite the entire chain as a privileged operator | **Accepted, partially.** Detectable only back to the last external checkpoint (proposed 60s). Stated, not solved. | §10.2               |
| Drop an event by crashing the broker              | Transactional outbox; dispatch rebuilt from PostgreSQL                                                            | §10.1               |
| Claim success for an action that never ran        | Outcomes require a consumed receipt; missing outcome stays visibly unknown                                        | INVARIANT 4, AUT-04 |

### 2.6 Abuse the platform surface

| Attack                                         | Control                                                                                                                                  | Trace              |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------ |
| Point a webhook at cloud metadata or localhost | URL validation blocking loopback, private, link-local and metadata ranges; no redirects; re-checked at connection time for DNS rebinding | §10.3              |
| Exhaust the decision path with deep payloads   | Bounded depth, length and key set before hashing or evaluating                                                                           | §7.1               |
| ReDoS the evaluator                            | No arbitrary regex in the DSL; lint-enforced                                                                                             | §7.1               |
| Starve other tenants                           | Per-tenant and per-principal limits with predictable 429                                                                                 | AUT-06             |
| Harvest secrets from logs or traces            | Redaction before serialization; no tokens, prompts or full payloads logged                                                               | INVARIANT 13       |
| Force a fail-open by breaking a dependency     | No fail-open mode exists; failures return 503                                                                                            | INVARIANT 1, §13.2 |

## 3. Accepted risks

Named here so they are decisions rather than oversights.

1. **A compromised cloud administrator can rewrite history** up to the last signed
   checkpoint. Mitigated, not eliminated, by separately scoped signer and archive roles.
2. **Exactly-once execution across TrustOS and an external SaaS API is not achievable.**
   A consumed grant plus a buggy gateway can still call the destination twice. Depends on
   destination idempotency or reconciliation.
3. **An action already in flight cannot be recalled.** Suspension blocks new authority; it
   cannot cancel a consumed grant mid-execution.
4. **Gateway bypass is undetectable from TrustOS logs alone.** Requires destination-side
   log comparison, which is a deployment commitment from the partner.
5. **Ownership registration is not identity verification.** It records who is accountable,
   not who someone legally is or whether an agent is competent.

## 4. Revision log

| Wave | Change                                                     |
| ---- | ---------------------------------------------------------- |
| 0    | Initial model. Boundaries, attacker goals, accepted risks. |
